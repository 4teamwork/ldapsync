from ldap3 import ALL
from ldap3 import Connection
from ldap3 import MODIFY_REPLACE
from ldap3 import Server
from ldap3 import SUBTREE

import logging


logger = logging.getLogger('ldapsync')


def fetch_users(server, bind_dn, bind_pw, base_dn, filter, attributes):
    with Connection(server, bind_dn, bind_pw) as conn:
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=1000,
            generator=False,
        )
    return entries


def ensure_single_valued(value):
    if isinstance(value, list):
        if value:
            return value[0]
        else:
            return None
    else:
        return value


def sync(options):
    """Synchronize LDAP users"""
    src_options = options['source'].get()
    tgt_options = options['target'].get()
    attribute_mapping = options['attribute_mapping'].get()
    reverse_attribute_mapping = {v: k for k, v in attribute_mapping.items()}
    user_rdn = options['user_rdn'].get()

    src_server = Server(
        src_options['server'],
        port=src_options['port'],
        use_ssl=src_options.get('use_ssl', False),
        get_info=ALL,
    )
    tgt_server = Server(
        tgt_options['server'],
        port=tgt_options['port'],
        use_ssl=tgt_options.get('use_ssl', False),
        get_info=ALL,
    )

    src_entries = fetch_users(
        src_server,
        src_options['bind_dn'],
        src_options['bind_password'],
        src_options['user_base_dn'],
        src_options['user_filter'],
        list(attribute_mapping.keys()),
    )
    tgt_entries = fetch_users(
        tgt_server,
        tgt_options['bind_dn'],
        tgt_options['bind_password'],
        tgt_options['user_base_dn'],
        tgt_options['user_filter'],
        list(attribute_mapping.values()),
    )

    # Attributes may be single valued on one server and multi valued on the
    # other server. In this case we ensure single values on both sides.
    single_valued_attributes = set()
    for src_attr, tgt_attr in attribute_mapping.items():
        if (
            src_server.schema.attribute_types[src_attr].single_value
            or tgt_server.schema.attribute_types[tgt_attr].single_value
        ):
            single_valued_attributes.add(src_attr)
            single_valued_attributes.add(tgt_attr)

    src_items = {
        ensure_single_valued(
            entry["attributes"][reverse_attribute_mapping[user_rdn]]
        ): {
            attribute_mapping[key]: ensure_single_valued(value)
            if key in single_valued_attributes
            else value
            for key, value in entry["attributes"].items()
        }
        for entry in src_entries
    }

    tgt_items = {
        ensure_single_valued(entry["attributes"][user_rdn]): {
            key: ensure_single_valued(value)
            if key in single_valued_attributes
            else value
            for key, value in entry["attributes"].items()
        }
        for entry in tgt_entries
    }

    src_keys = set(src_items.keys())
    tgt_keys = set(tgt_items.keys())

    added = src_keys - tgt_keys
    deleted = tgt_keys - src_keys
    existing = src_keys & tgt_keys
    modified = {}
    for key in existing:
        diff = set(src_items[key].items()) ^ set(tgt_items[key].items())
        if diff:
            attributes = dict(diff).keys()
            modified[key] = attributes

    user_objectclass = options['user_objectclass'].get()

    added_count = 0
    deleted_count = 0
    modified_count = 0
    failed_count = 0

    with Connection(tgt_server, tgt_options['bind_dn'],
                    tgt_options['bind_password']) as conn:
        for key in added:
            attrs = {key: value for key, value in src_items[key].items() if value}
            dn = f'{user_rdn}={attrs[user_rdn]},{tgt_options["user_base_dn"]}'
            res = conn.add(
                dn,
                object_class=user_objectclass,
                attributes=attrs,
            )
            if not res:
                failed_count += 1
                logger.warning('Could not add %s. %s', dn, conn.result)
            else:
                added_count += 1
                logger.debug('Added %s', dn)

        for key in deleted:
            attrs = {key: value for key, value in tgt_items[key].items() if value}
            dn = f'{user_rdn}={attrs[user_rdn]},{tgt_options["user_base_dn"]}'
            res = conn.delete(dn)
            if not res:
                failed_count += 1
                logger.warning('Could not delete %s. %s', dn, conn.result)
            else:
                deleted_count += 1
                logger.debug('Deleted %s', dn)

        for key, modified_attrs in modified.items():
            attrs = {key: value for key, value in src_items[key].items() if value}
            dn = f'{user_rdn}={attrs[user_rdn]},{tgt_options["user_base_dn"]}'
            changes = {}
            for modified_attr in modified_attrs:
                changes[modified_attr] = [(MODIFY_REPLACE, [attrs[modified_attr]])]
            res = conn.modify(dn, changes)
            if not res:
                failed_count += 1
                logger.warning(
                    'Could not modify attributes %s for %s. %s',
                    list(modified_attrs), dn, conn.result)
            else:
                modified_count += 1
                logger.debug('Modified attributes %s for %s.', list(modified_attrs), dn)

    print(
        f'Processed {len(src_keys)} entries. Added: {added_count}, deleted: '
        f'{deleted_count}, modified: {modified_count}, failed: {failed_count}'
    )
