"""Group-based tenant management for FreeIPA.

Tenants are deliberately represented with existing FreeIPA objects instead of
a new LDAP subtree:

* ``tenant-<name>`` is the group whose members belong to the tenant.
* ``tenant-<name>-admins`` is the group allowed to manage that tenant.
* ``tenant-<name>-hosts`` is the host group the tenant may access.
* ``tenant-<name>`` is an HBAC allow rule generated from those groups.

The command never accepts arbitrary user, host, or service memberships.  It
always derives them from the tenant groups, which prevents a tenant
administrator from extending their rule to another tenant's resources.
"""

from collections import namedtuple
import re

from ipalib import Command, Flag, Str, _, errors, output
from ipalib.plugable import Registry
from ipalib.request import context

from ipaserver.plugins.privilege import principal_has_privilege


__doc__ = _("""
Group-based multi-tenant access control

Tenants are isolated with tenant-specific groups and a generated HBAC rule.
The tenant member group is the only user group in the rule and the tenant host
group is the only host group in the rule.  This prevents a rule generated for
one tenant from granting access to another tenant's users or hosts.

Each tenant has a delegated administrator group.  Members of that group may
manage their own tenant, but cannot manage another tenant.  Global HBAC
administrators (and the built-in admins group) may manage every tenant.

EXAMPLES:

 Create a tenant and disable the global allow_all rule.  Missing groups are
 created automatically.  The allow_all rule must not stay enabled, otherwise
 it bypasses every tenant rule:
   ipa tenant-add acme --service sshd --disable-allow-all

 Add an administrator for the tenant:
   ipa group-add-member tenant-acme-admins --users=alice

 Display the generated rule:
   ipa tenant-show acme

 Remove the generated HBAC rule but keep the tenant groups:
   ipa tenant-del acme

 Remove the rule and the automatically created groups:
   ipa tenant-del acme --purge
""")


register = Registry()

TENANT_RULE_PREFIX = 'tenant-'
TENANT_ADMIN_SUFFIX = '-admins'
TENANT_HOST_SUFFIX = '-hosts'
TENANT_DEFAULT_SERVICE = 'sshd'

TENANT_GROUP_MARKER = 'FreeIPA tenant group'
TENANT_RULE_MARKER = 'FreeIPA tenant rule'

_TENANT_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
_TENANT_RULE_DESCRIPTION_RE = re.compile(
    r'^FreeIPA tenant rule '
    r'\(tenant=(?P<tenant>[^;)]+); '
    r'group=(?P<group>[^;)]+); '
    r'hostgroup=(?P<hostgroup>[^)]+)\)'
)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _first(value):
    values = _as_list(value)
    return values[0] if values else None


def _normalize_names(values):
    if isinstance(values, str):
        values = (values,)
    result = []
    seen = set()
    for value in values or ():
        if value is None:
            continue
        name = str(value).strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(name)
    return tuple(result)


def _coerce_single_name(value, parameter):
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise errors.ValidationError(
                name=parameter,
                error=_('Exactly one name is required'),
            )
        value = value[0]
    return value


def validate_tenant_name(name):
    """Return a normalized tenant name or raise a clear validation error."""
    if not isinstance(name, str):
        raise errors.ValidationError(
            name='cn',
            error=_('Tenant name must be a string'),
        )
    name = name.strip()
    if not _TENANT_NAME_RE.match(name):
        raise errors.ValidationError(
            name='cn',
            error=_(
                'Tenant name must start with a letter or digit, contain only '
                'letters, digits, "_", ".", or "-", and be at most 64 '
                'characters long'
            ),
        )
    return name


def validate_member_name(value, parameter):
    """Validate a group/host group name used in a generated rule."""
    if not isinstance(value, str):
        raise errors.ValidationError(
            name=parameter,
            error=_('Name must be a string'),
        )
    value = value.strip()
    if not value:
        raise errors.ValidationError(
            name=parameter,
            error=_('Name cannot be empty'),
        )
    if any(char in value for char in ';),'):
        raise errors.ValidationError(
            name=parameter,
            error=_('Name contains characters reserved for tenant binding'),
        )
    return value


class TenantRuleSpec(namedtuple(
        'TenantRuleSpec',
        'tenant group hostgroup services service_groups description')):
    """The immutable description of one tenant to HBAC rule mapping."""

    __slots__ = ()

    def __new__(cls, tenant, group, hostgroup, services=(),
                service_groups=(), description=''):
        tenant = validate_tenant_name(tenant)
        group = validate_member_name(group, 'group')
        hostgroup = validate_member_name(hostgroup, 'hostgroup')
        services = _normalize_names(services)
        service_groups = _normalize_names(service_groups)
        for service in services:
            validate_member_name(service, 'hbacsvc')
        for service_group in service_groups:
            validate_member_name(service_group, 'hbacsvcgroup')
        if not services and not service_groups:
            raise errors.ValidationError(
                name='hbacsvc',
                error=_('At least one HBAC service or service group is '
                        'required'),
            )

        return super().__new__(
            cls,
            tenant,
            group,
            hostgroup,
            services,
            service_groups,
            str(description or ''),
        )

    @property
    def rule_name(self):
        return '{}{}'.format(TENANT_RULE_PREFIX, self.tenant)

    @property
    def admin_group(self):
        return '{}{}{}'.format(
            TENANT_RULE_PREFIX, self.tenant, TENANT_ADMIN_SUFFIX)

    @property
    def host_group(self):
        return '{}{}{}'.format(
            TENANT_RULE_PREFIX, self.tenant, TENANT_HOST_SUFFIX)

    @property
    def rule_description(self):
        marker = (
            '{} (tenant={}; group={}; hostgroup={})'.format(
                TENANT_RULE_MARKER, self.tenant, self.group, self.hostgroup)
        )
        if self.description:
            return '{} {}'.format(marker, self.description)
        return marker


HbacRulePlan = namedtuple(
    'HbacRulePlan',
    'rule_name rule_options user_options host_options service_options',
)


def build_hbac_rule_plan(spec):
    """Build a deterministic HBAC rule plan from tenant group metadata.

    The returned dictionaries are intentionally shaped for the existing
    ``hbacrule_*`` commands.  No ``*category=all`` option is ever emitted:
    rules generated here must stay scoped to the tenant's groups.
    """
    service_options = {}
    if spec.services:
        service_options['hbacsvc'] = list(spec.services)
    if spec.service_groups:
        service_options['hbacsvcgroup'] = list(spec.service_groups)

    return HbacRulePlan(
        rule_name=spec.rule_name,
        rule_options={'description': spec.rule_description},
        user_options={'group': [spec.group]},
        host_options={'hostgroup': [spec.hostgroup]},
        service_options=service_options,
    )


def parse_tenant_rule_description(entry):
    """Extract tenant binding metadata from a generated rule entry."""
    description = _first(entry.get('description'))
    if not description:
        return None
    match = _TENANT_RULE_DESCRIPTION_RE.match(description)
    if match is None:
        return None
    return {key: value.strip() for key, value in match.groupdict().items()}


def is_tenant_rule(entry, tenant=None):
    metadata = parse_tenant_rule_description(entry)
    if metadata is None:
        return False
    if tenant is None:
        return True
    return metadata['tenant'].lower() == tenant.lower()


def _names_from_entry(entry, attribute):
    return {str(value).lower() for value in _as_list(entry.get(attribute))}


def validate_rule_isolation(entry, spec):
    """Reject an existing rule that grants access outside the tenant."""
    for category in ('usercategory', 'hostcategory', 'servicecategory'):
        value = _first(entry.get(category))
        if value is not None and str(value).lower() == 'all':
            raise errors.TenantIsolationError(
                tenant=spec.tenant,
                reason=_(
                    'HBAC rule uses %(category)s="all" and is not '
                    'tenant-isolated'
                ) % {'category': category},
            )

    allowed_users = {spec.group.lower()}
    rule_users = _names_from_entry(entry, 'memberuser_group')
    rule_users.update(_names_from_entry(entry, 'memberuser_user'))
    if rule_users - allowed_users:
        raise errors.TenantIsolationError(
            tenant=spec.tenant,
            reason=_(
                'HBAC rule contains users or groups outside tenant group '
                '"%(group)s"'
            ) % {'group': spec.group},
        )

    allowed_hosts = {spec.hostgroup.lower()}
    rule_hosts = _names_from_entry(entry, 'memberhost_hostgroup')
    rule_hosts.update(_names_from_entry(entry, 'memberhost_host'))
    if rule_hosts - allowed_hosts:
        raise errors.TenantIsolationError(
            tenant=spec.tenant,
            reason=_(
                'HBAC rule contains hosts or host groups outside tenant '
                'host group "%(hostgroup)s"'
            ) % {'hostgroup': spec.hostgroup},
        )

    allowed_services = {name.lower() for name in spec.services}
    rule_services = _names_from_entry(entry, 'memberservice_hbacsvc')
    if rule_services - allowed_services:
        raise errors.TenantIsolationError(
            tenant=spec.tenant,
            reason=_('HBAC rule contains services outside the tenant scope'),
        )

    allowed_service_groups = {
        name.lower() for name in spec.service_groups
    }
    rule_service_groups = _names_from_entry(
        entry, 'memberservice_hbacsvcgroup')
    if rule_service_groups - allowed_service_groups:
        raise errors.TenantIsolationError(
            tenant=spec.tenant,
            reason=_(
                'HBAC rule contains service groups outside the tenant scope'
            ),
        )


def check_tenant_access(operation, tenant, principal, *,
                        is_global_admin=False, admin_users=(),
                        admin_groups=(), caller_groups=(), tenant_exists=True):
    """Authorize a tenant operation without relying on hidden global state.

    ``operation`` is one of ``add``, ``show``, or ``del``.  Global
    administrators may operate on every tenant.  Other callers must be a
    direct member of the tenant's administrator group, or a member of a group
    nested in that administrator group.
    """
    if is_global_admin:
        return

    if not principal:
        raise errors.TenantIsolationError(
            tenant=tenant,
            reason=_('an authenticated principal is required'),
        )

    user = str(principal).split('@', 1)[0].lower()
    if user in {str(value).lower() for value in admin_users}:
        return
    caller_groups = {str(value).lower() for value in caller_groups}
    admin_groups = {str(value).lower() for value in admin_groups}
    if caller_groups.intersection(admin_groups):
        return

    admin_group = '{}{}{}'.format(
        TENANT_RULE_PREFIX, tenant, TENANT_ADMIN_SUFFIX)
    if operation == 'add' and not tenant_exists:
        reason = _('only global administrators can create a new tenant')
    else:
        reason = _(
            'principal "%(principal)s" is not a member of tenant '
            'administrator group "%(group)s"'
        ) % {'principal': principal, 'group': admin_group}
    raise errors.TenantIsolationError(tenant=tenant, reason=reason)


def _format_summary(tenant, rule_name):
    return _('Tenant "%(tenant)s" is mapped to HBAC rule "%(rule)s"') % {
        'tenant': tenant,
        'rule': rule_name,
    }


def _has_failures(value):
    if isinstance(value, dict):
        return any(_has_failures(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_has_failures(item) for item in value)
    return bool(value)


class _TenantCommand(Command):
    """Shared plumbing for tenant add/show/delete."""

    def _principal(self):
        request_context = getattr(self, 'context', None)
        principal = getattr(request_context, 'principal', None)
        if not principal:
            principal = getattr(context, 'principal', None)
        return principal

    def _group_members(self, group_name):
        try:
            entry = self.api.Command['group_show'](
                group_name, all=True)['result']
        except errors.NotFound:
            return set(), set()
        except (errors.ACIError, errors.ExecutionError):
            return set(), set()
        return (
            set(_as_list(entry.get('member_user'))),
            set(_as_list(entry.get('member_group'))),
        )

    def _caller_groups(self, principal):
        if not principal:
            return set()
        user = str(principal).split('@', 1)[0]
        try:
            entry = self.api.Command['user_show'](user, all=True)['result']
        except (errors.NotFound, errors.ACIError, errors.ExecutionError):
            return set()
        groups = set(_as_list(entry.get('memberof_group')))
        groups.update(_as_list(entry.get('memberofindirect_group')))
        return groups

    def _is_global_admin(self, principal):
        if not principal:
            return False
        try:
            if principal_has_privilege(
                    self.api, principal, 'HBAC Administrator'):
                return True
        except (errors.PublicError, AttributeError, IndexError, KeyError,
                TypeError):
            pass

        admin_users, admin_groups = self._group_members('admins')
        user = str(principal).split('@', 1)[0].lower()
        if user in {str(value).lower() for value in admin_users}:
            return True
        caller_groups = {
            str(value).lower() for value in self._caller_groups(principal)
        }
        admin_groups = {str(value).lower() for value in admin_groups}
        return bool(caller_groups.intersection(admin_groups))

    def _authorize(self, operation, tenant, tenant_exists=True):
        principal = self._principal()
        if self._is_global_admin(principal):
            return True
        admin_users, admin_groups = self._group_members(
            '{}{}{}'.format(TENANT_RULE_PREFIX, tenant, TENANT_ADMIN_SUFFIX))
        check_tenant_access(
            operation,
            tenant,
            principal,
            is_global_admin=False,
            admin_users=admin_users,
            admin_groups=admin_groups,
            caller_groups=self._caller_groups(principal),
            tenant_exists=tenant_exists,
        )
        return False

    def _get_rule(self, rule_name):
        try:
            return self.api.Command['hbacrule_show'](
                rule_name, all=True)['result']
        except errors.NotFound:
            return None

    def _group_exists(self, group_name):
        try:
            self.api.Command['group_show'](group_name)
            return True
        except errors.NotFound:
            return False

    def _allow_all_enabled(self):
        entry = self._get_rule('allow_all')
        if entry is None:
            return False
        value = _first(entry.get('ipaenabledflag'))
        return value is True or str(value).lower() in ('1', 'true')

    def _validate_rule_binding(self, entry, spec):
        metadata = parse_tenant_rule_description(entry)
        if metadata is None:
            raise errors.TenantIsolationError(
                tenant=spec.tenant,
                reason=_(
                    'HBAC rule "%(rule)s" exists but is not managed by the '
                    'tenant plugin'
                ) % {'rule': spec.rule_name},
            )
        if (metadata['tenant'].lower() != spec.tenant.lower()
                or metadata['group'].lower() != spec.group.lower()
                or metadata['hostgroup'].lower() != spec.hostgroup.lower()):
            raise errors.TenantIsolationError(
                tenant=spec.tenant,
                reason=_(
                    'HBAC rule "%(rule)s" is bound to tenant "%(owner)s", '
                    'group "%(group)s", and host group "%(hostgroup)s"'
                ) % {
                    'rule': spec.rule_name,
                    'owner': metadata['tenant'],
                    'group': metadata['group'],
                    'hostgroup': metadata['hostgroup'],
                },
            )
        validate_rule_isolation(entry, spec)

    def _ensure_group(self, group_name, description, command_name):
        try:
            self.api.Command[command_name](group_name)
        except errors.NotFound:
            kwargs = {
                'description': '{} ({}): {}'.format(
                    TENANT_GROUP_MARKER, group_name, description),
            }
            if command_name == 'group_add':
                kwargs['nonposix'] = True
            self.api.Command[command_name](group_name, **kwargs)

    def _ensure_rule_prerequisites(self, spec):
        for service in spec.services:
            try:
                self.api.Command['hbacsvc_show'](service)
            except errors.NotFound:
                raise errors.NotFound(
                    reason=_('HBAC service "%(service)s" does not exist') % {
                        'service': service,
                    },
                )
        for service_group in spec.service_groups:
            try:
                self.api.Command['hbacsvcgroup_show'](service_group)
            except errors.NotFound:
                raise errors.NotFound(
                    reason=_(
                        'HBAC service group "%(group)s" does not exist'
                    ) % {'group': service_group},
                )

        self._ensure_group(
            spec.group,
            'members of tenant {}'.format(spec.tenant),
            'group_add',
        )
        self._ensure_group(
            spec.admin_group,
            'administrators of tenant {}'.format(spec.tenant),
            'group_add',
        )
        self._ensure_group(
            spec.hostgroup,
            'target hosts for tenant {}'.format(spec.tenant),
            'hostgroup_add',
        )

    def _apply_rule_membership(self, plan):
        calls = [
            ('hbacrule_add_user', plan.user_options),
            ('hbacrule_add_host', plan.host_options),
        ]
        if plan.service_options:
            calls.append(('hbacrule_add_service', plan.service_options))

        for command_name, options in calls:
            result = self.api.Command[command_name](
                plan.rule_name, **options)
            if isinstance(result, dict) and _has_failures(
                    result.get('failed')):
                raise errors.TenantIsolationError(
                    tenant=plan.rule_name[len(TENANT_RULE_PREFIX):],
                    reason=_(
                        'could not enforce tenant membership through '
                        '%(command)s: %(failed)s'
                    ) % {
                        'command': command_name,
                        'failed': result.get('failed'),
                    },
                )


@register()
class tenant_add(_TenantCommand):
    __doc__ = _('Create or update a group-isolated tenant HBAC rule.')

    takes_args = (
        Str(
            'cn',
            cli_name='name',
            label=_('Tenant name'),
        ),
    )

    takes_options = (
        Str(
            'group?',
            cli_name='group',
            label=_('Tenant member group'),
            doc=_('Existing or new group containing the tenant users'),
        ),
        Str(
            'hostgroup?',
            cli_name='hostgroup',
            label=_('Tenant host group'),
            doc=_('Existing or new host group containing tenant hosts'),
        ),
        Str(
            'hbacsvc*',
            cli_name='service',
            label=_('HBAC service'),
            doc=_('HBAC service allowed for the tenant'),
        ),
        Str(
            'hbacsvcgroup*',
            cli_name='servicegroup',
            label=_('HBAC service group'),
            doc=_('HBAC service group allowed for the tenant'),
        ),
        Str(
            'description?',
            cli_name='desc',
            label=_('Description'),
        ),
        Flag(
            'disable_allow_all',
            cli_name='disable_allow_all',
            label=_('Disable the default allow_all rule'),
            doc=_(
                'Disable the global allow_all HBAC rule after the tenant '
                'rule has been generated'
            ),
            default=False,
        ),
    )

    has_output = (
        output.Output('result', dict, _('Generated tenant HBAC rule')),
        output.summary,
    )

    def execute(self, cn, **options):
        tenant = validate_tenant_name(cn)
        rule_name = '{}{}'.format(TENANT_RULE_PREFIX, tenant)
        existing = self._get_rule(rule_name)
        metadata = (
            parse_tenant_rule_description(existing)
            if existing is not None else None
        )

        default_group = '{}{}'.format(TENANT_RULE_PREFIX, tenant)
        default_hostgroup = '{}{}{}'.format(
            TENANT_RULE_PREFIX, tenant, TENANT_HOST_SUFFIX)
        group = _coerce_single_name(options.get('group'), 'group') or (
            metadata['group'] if metadata else default_group)
        hostgroup = _coerce_single_name(
            options.get('hostgroup'), 'hostgroup') or (
            metadata['hostgroup'] if metadata else default_hostgroup)
        services = _normalize_names(options.get('hbacsvc'))
        service_groups = _normalize_names(options.get('hbacsvcgroup'))
        if existing is not None and not services and not service_groups:
            services = tuple(
                _as_list(existing.get('memberservice_hbacsvc')))
            service_groups = tuple(
                _as_list(existing.get('memberservice_hbacsvcgroup')))
        if not services and not service_groups:
            services = (TENANT_DEFAULT_SERVICE,)

        spec = TenantRuleSpec(
            tenant=tenant,
            group=group,
            hostgroup=hostgroup,
            services=services,
            service_groups=service_groups,
            description=options.get('description') or '',
        )
        plan = build_hbac_rule_plan(spec)

        is_global_admin = self._authorize(
            'add',
            tenant,
            tenant_exists=(
                existing is not None or self._group_exists(spec.admin_group)
            ),
        )
        if existing is not None:
            self._validate_rule_binding(existing, spec)
        elif not is_global_admin:
            if (spec.group.lower() != default_group.lower()
                    or spec.hostgroup.lower() != default_hostgroup.lower()):
                raise errors.TenantIsolationError(
                    tenant=tenant,
                    reason=_(
                        'tenant administrators cannot rebind a tenant to '
                        'other groups; expected group "%(group)s" and host '
                        'group "%(hostgroup)s"'
                    ) % {
                        'group': default_group,
                        'hostgroup': default_hostgroup,
                    },
                )

        allow_all_enabled = self._allow_all_enabled()
        if allow_all_enabled and not options.get('disable_allow_all'):
            raise errors.TenantIsolationError(
                tenant=tenant,
                reason=_(
                    'HBAC rule "allow_all" is enabled and would bypass tenant '
                    'isolation; disable it first or pass '
                    '--disable-allow-all'
                ),
            )
        self._ensure_rule_prerequisites(spec)

        if existing is None:
            self.api.Command['hbacrule_add'](
                plan.rule_name, **plan.rule_options)
        else:
            self.api.Command['hbacrule_mod'](
                plan.rule_name, **plan.rule_options)
            enabled = _first(existing.get('ipaenabledflag'))
            if enabled is False or str(enabled).lower() in ('0', 'false'):
                self.api.Command['hbacrule_enable'](plan.rule_name)

        self._apply_rule_membership(plan)
        if allow_all_enabled and options.get('disable_allow_all'):
            self.api.Command['hbacrule_disable']('allow_all')

        result = {
            'cn': plan.rule_name,
            'tenant': spec.tenant,
            'group': spec.group,
            'admin_group': spec.admin_group,
            'hostgroup': spec.hostgroup,
            'hbacsvc': list(spec.services),
            'hbacsvcgroup': list(spec.service_groups),
            'description': spec.rule_description,
            'managed': True,
            'created': existing is None,
            'allow_all_disabled': bool(
                allow_all_enabled and options.get('disable_allow_all')),
        }
        return {
            'result': result,
            'summary': _format_summary(tenant, plan.rule_name),
        }


@register()
class tenant_show(_TenantCommand):
    __doc__ = _('Display the HBAC rule generated for a tenant.')

    takes_args = (
        Str(
            'cn',
            cli_name='name',
            label=_('Tenant name'),
        ),
    )

    has_output = (
        output.Output('result', dict, _('Tenant HBAC rule')),
    )

    def execute(self, cn, **options):
        tenant = validate_tenant_name(cn)
        rule_name = '{}{}'.format(TENANT_RULE_PREFIX, tenant)
        entry = self._get_rule(rule_name)
        self._authorize('show', tenant, tenant_exists=entry is not None)
        if entry is None:
            raise errors.NotFound(
                reason=_('Tenant "%(tenant)s" does not exist') % {
                    'tenant': tenant,
                },
            )

        metadata = parse_tenant_rule_description(entry)
        if metadata is None or metadata['tenant'].lower() != tenant.lower():
            raise errors.NotFound(
                reason=_('Tenant "%(tenant)s" does not exist') % {
                    'tenant': tenant,
                },
            )

        return {
            'result': {
                'cn': rule_name,
                'tenant': tenant,
                'group': metadata['group'],
                'admin_group': '{}{}{}'.format(
                    TENANT_RULE_PREFIX, tenant, TENANT_ADMIN_SUFFIX),
                'hostgroup': metadata['hostgroup'],
                'hbacsvc': _as_list(entry.get('memberservice_hbacsvc')),
                'hbacsvcgroup': _as_list(
                    entry.get('memberservice_hbacsvcgroup')),
                'description': _first(entry.get('description')),
                'managed': True,
            },
        }


@register()
class tenant_del(_TenantCommand):
    __doc__ = _('Delete the HBAC rule generated for a tenant.')

    takes_args = (
        Str(
            'cn',
            cli_name='name',
            label=_('Tenant name'),
        ),
    )

    takes_options = (
        Flag(
            'purge',
            cli_name='purge',
            label=_('Purge tenant groups'),
            doc=_('Also delete groups created and managed by this plugin'),
            default=False,
        ),
    )

    has_output = (
        output.Output('result', dict, _('Deleted tenant HBAC rule')),
        output.summary,
    )

    def _purge_group(self, group_name, show_name, del_name, purged):
        try:
            entry = self.api.Command[show_name](
                group_name, all=True)['result']
        except errors.NotFound:
            return
        description = _first(entry.get('description')) or ''
        if not description.startswith(TENANT_GROUP_MARKER):
            return
        self.api.Command[del_name](group_name)
        purged.append(group_name)

    def execute(self, cn, **options):
        tenant = validate_tenant_name(cn)
        rule_name = '{}{}'.format(TENANT_RULE_PREFIX, tenant)
        entry = self._get_rule(rule_name)
        self._authorize('del', tenant, tenant_exists=entry is not None)
        if entry is None:
            raise errors.NotFound(
                reason=_('Tenant "%(tenant)s" does not exist') % {
                    'tenant': tenant,
                },
            )

        metadata = parse_tenant_rule_description(entry)
        if metadata is None or metadata['tenant'].lower() != tenant.lower():
            raise errors.NotFound(
                reason=_('Tenant "%(tenant)s" does not exist') % {
                    'tenant': tenant,
                },
            )

        self.api.Command['hbacrule_del'](rule_name)

        purged = []
        if options.get('purge'):
            self._purge_group(
                metadata['group'], 'group_show', 'group_del', purged)
            self._purge_group(
                '{}{}{}'.format(
                    TENANT_RULE_PREFIX, tenant, TENANT_ADMIN_SUFFIX),
                'group_show',
                'group_del',
                purged,
            )
            self._purge_group(
                metadata['hostgroup'],
                'hostgroup_show',
                'hostgroup_del',
                purged,
            )

        return {
            'result': {
                'cn': rule_name,
                'tenant': tenant,
                'deleted': True,
                'purged': purged,
            },
            'summary': _('Deleted tenant HBAC rule "%(rule)s"') % {
                'rule': rule_name,
            },
        }
