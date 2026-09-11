"""OpTC eCAR records: preserve event identity and directed information flow."""
from datetime import datetime, timezone


def timestamp_ns(value):
    delta = datetime.fromisoformat(value).astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def parse_event(raw):
    props = raw.get('properties', {})
    kind, action = raw['object'], raw['action']
    if kind not in {'FILE', 'PROCESS', 'FLOW'}:
        return None
    actor, obj = raw['actorID'], raw['objectID']
    actor_label = props.get('image_path') or f"进程 PID {raw.get('pid', '?')}"
    if kind == 'FILE':
        target_label = props.get('file_path') or obj
    elif kind == 'FLOW':
        target_label = f"{props.get('src_ip', '?')}:{props.get('src_port', '?')} → {props.get('dest_ip', '?')}:{props.get('dest_port', '?')}"
    elif action == 'CREATE' and props.get('parent_image_path'):
        # eCAR creation records identify the child image and its parent's image.
        actor_label = props['parent_image_path']
        target_label = props.get('image_path') or obj
    else:
        target_label = props.get('target_image_path') or obj
    reverse = (kind == 'FILE' and action == 'READ') or (kind == 'FLOW' and props.get('direction', '').lower() == 'inbound')
    source, target = (obj, actor) if reverse else (actor, obj)
    labels = {actor: actor_label, obj: target_label}
    types = {actor: 'process', obj: {'FILE': 'file', 'PROCESS': 'process', 'FLOW': 'flow'}[kind]}
    return dict(id=raw['id'], source=source, target=target,
                source_label=labels[source], target_label=labels[target],
                source_type=types[source], target_type=types[target],
                relation=f'{kind}_{action}', timestamp=raw['timestamp'],
                timestamp_ns=timestamp_ns(raw['timestamp']),
                host=raw['hostname'], raw=raw)


def signature(edge):
    """Semantic interaction frequency; ephemeral client ports are not behaviors."""
    raw = edge['raw']
    props = raw.get('properties', {})
    if raw['object'] == 'FLOW':
        inbound = props.get('direction', '').lower() == 'inbound'
        remote = 'src' if inbound else 'dest'
        service = 'dest_port'
        return ('flow', props.get('image_path', '').lower(), edge['relation'],
                props.get('direction', '').lower(), props.get(remote + '_ip', ''),
                str(props.get(service, '')), str(props.get('l4protocol', '')))
    return (edge['source_label'].lower(), edge['relation'], edge['target_label'].lower())
