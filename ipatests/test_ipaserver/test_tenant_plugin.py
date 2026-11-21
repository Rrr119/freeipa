from unittest import mock

import pytest

from ipalib import errors
from ipaserver.plugins import tenant as tenant_plugin


pytestmark = pytest.mark.tier0


def _spec(**overrides):
    values = {
        'tenant': 'acme',
        'group': 'tenant-acme',
        'hostgroup': 'tenant-acme-hosts',
        'services': ('sshd',),
    }
    values.update(overrides)
    return tenant_plugin.TenantRuleSpec(**values)


def test_rule_plan_defaults_to_sshd_and_tenant_groups():
    spec = _spec()
    plan = tenant_plugin.build_hbac_rule_plan(spec)

    assert plan.rule_name == 'tenant-acme'
    assert plan.user_options == {'group': ['tenant-acme']}
    assert plan.host_options == {'hostgroup': ['tenant-acme-hosts']}
    assert plan.service_options == {'hbacsvc': ['sshd']}
    assert not any(key.endswith('category') for key in plan.rule_options)
    tenant_plugin.validate_rule_isolation(
        {
            'memberuser_group': ['tenant-acme'],
            'memberhost_hostgroup': ['tenant-acme-hosts'],
            'memberservice_hbacsvc': ['sshd'],
        },
        spec,
    )
    with pytest.raises(errors.TenantIsolationError):
        tenant_plugin.validate_rule_isolation(
            {'usercategory': ['all']}, spec)


def test_tenant_add_uses_existing_hbac_api(monkeypatch):
    calls = []
    state = {'tenant_admin': False}

    def command(name):
        def invoke(*args, **kwargs):
            calls.append((name, args, kwargs))
            if name == 'group_show':
                if (state['tenant_admin']
                        and args[0] == 'tenant-acme-admins'):
                    return {'result': {'member_user': ['alice']}}
                raise errors.NotFound(reason='missing')
            if name in ('hbacrule_show', 'hostgroup_show'):
                raise errors.NotFound(reason='missing')
            if name == 'hbacsvc_show':
                return {'result': {'cn': [args[0]]}}
            if name in (
                    'hbacrule_add_user', 'hbacrule_add_host',
                    'hbacrule_add_service'):
                return {'completed': 1, 'failed': {}}
            return {'result': {}}
        return invoke

    api_mock = mock.MagicMock()
    api_mock.Command = {
        name: command(name)
        for name in (
            'hbacrule_show', 'hbacrule_add', 'hbacrule_mod',
            'hbacrule_add_user', 'hbacrule_add_host',
            'hbacrule_add_service', 'hbacrule_enable', 'hbacrule_disable',
            'hbacsvc_show', 'hbacsvcgroup_show', 'group_show', 'group_add',
            'hostgroup_show', 'hostgroup_add', 'user_show',
        )
    }
    monkeypatch.setattr(
        tenant_plugin, 'principal_has_privilege', lambda *args: True)
    monkeypatch.setattr(
        tenant_plugin.context, 'principal', 'admin@EXAMPLE.COM',
        raising=False)

    result = tenant_plugin.tenant_add(api_mock).execute('acme')

    assert result['result']['cn'] == 'tenant-acme'
    assert ('hbacrule_add_user', ('tenant-acme',),
            {'group': ['tenant-acme']}) in calls
    assert ('hbacrule_add_host', ('tenant-acme',),
            {'hostgroup': ['tenant-acme-hosts']}) in calls
    assert ('hbacrule_add_service', ('tenant-acme',),
            {'hbacsvc': ['sshd']}) in calls
    assert all(
        'category' not in kwargs
        for name, args, kwargs in calls
        if name.startswith('hbacrule_')
    )

    state['tenant_admin'] = True
    monkeypatch.setattr(
        tenant_plugin.context, 'principal', 'alice@EXAMPLE.COM')
    monkeypatch.setattr(
        tenant_plugin, 'principal_has_privilege', lambda *args: False)
    with pytest.raises(errors.TenantIsolationError) as exc_info:
        tenant_plugin.tenant_add(api_mock).execute('acme', group='admins')

    assert 'cannot rebind' in str(exc_info.value)


def test_rule_plan_deduplicates_services_case_insensitively():
    spec = _spec(services=('sshd', 'SSHD', 'sshd', ' httpd '))
    plan = tenant_plugin.build_hbac_rule_plan(spec)

    assert plan.service_options['hbacsvc'] == ['sshd', 'httpd']


def test_rule_plan_supports_hbac_service_groups():
    spec = _spec(services=(), service_groups=('web-services',))
    plan = tenant_plugin.build_hbac_rule_plan(spec)

    assert 'hbacsvc' not in plan.service_options
    assert plan.service_options == {'hbacsvcgroup': ['web-services']}


def test_rule_description_records_group_isolation_binding():
    spec = _spec(group='acme-users', hostgroup='acme-hosts')
    metadata = tenant_plugin.parse_tenant_rule_description(
        {'description': [spec.rule_description]})

    assert metadata == {
        'tenant': 'acme',
        'group': 'acme-users',
        'hostgroup': 'acme-hosts',
    }


def test_rule_and_admin_group_names_are_tenant_namespaced():
    spec = _spec()

    assert spec.rule_name == 'tenant-acme'
    assert spec.admin_group == 'tenant-acme-admins'
    assert spec.host_group == 'tenant-acme-hosts'


def test_invalid_tenant_name_is_rejected_before_rule_generation():
    with pytest.raises(errors.ValidationError) as exc_info:
        _spec(tenant='../other-tenant')

    assert exc_info.value.name == 'cn'


def test_rule_generation_rejects_empty_service_set():
    with pytest.raises(errors.ValidationError) as exc_info:
        _spec(services=(), service_groups=())

    assert exc_info.value.name == 'hbacsvc'


def test_global_admin_is_allowed_to_create_a_new_tenant():
    tenant_plugin.check_tenant_access(
        'add',
        'acme',
        'admin@EXAMPLE.COM',
        is_global_admin=True,
        tenant_exists=False,
    )


def test_tenant_admin_is_confined_to_own_tenant():
    tenant_plugin.check_tenant_access(
        'add',
        'acme',
        'alice@EXAMPLE.COM',
        admin_users=('alice',),
        tenant_exists=True,
    )

    with pytest.raises(errors.TenantIsolationError) as exc_info:
        tenant_plugin.check_tenant_access(
            'del',
            'other',
            'alice@EXAMPLE.COM',
            admin_users=('bob',),
            tenant_exists=True,
        )

    assert exc_info.value.tenant == 'other'
    assert exc_info.value.errno == 2101
    assert 'tenant-other-admins' in str(exc_info.value)
