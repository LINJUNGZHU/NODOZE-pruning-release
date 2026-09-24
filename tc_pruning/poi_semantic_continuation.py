"""Find a process execution immediately after a POI writes the same file name.

This uses only CDM event fields and the already declared investigation POI. It
does not read attack labels or detector annotations.
"""

from __future__ import annotations

import ntpath
import json
import re
from typing import Iterable


def _file_basename(semantic: object) -> str:
    if not isinstance(semantic, str) or not semantic.startswith('file:'):
        return ''
    path = semantic[5:].strip().strip('"')
    return ntpath.basename(path).casefold()


def _socket_destination_group(semantic: object) -> str:
    """Group IPv4 destinations by /24 to avoid retaining an entire scan."""
    if not isinstance(semantic, str) or not semantic.startswith('socket:'):
        return ''
    host = semantic[7:].rsplit(':', 1)[0]
    octets = host.split('.')
    if len(octets) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in octets):
        return '.'.join(octets[:3])
    return host


def _socket_destination_port(semantic: object) -> int:
    if not isinstance(semantic, str) or not semantic.startswith('socket:'):
        return 65536
    port = semantic.rsplit(':', 1)[-1]
    return int(port) if port.isdigit() else 65536


def _process_basename(semantic: object) -> str:
    if not isinstance(semantic, str) or not semantic.startswith('process:'):
        return ''
    command = semantic[8:].strip()
    return ntpath.basename(command.split()[0]).casefold() if command else ''


def forward_file_execution(
    rows: list[dict], *, max_execution_ns: int = 2_000_000_000,
    max_forward_ns: int = 360_000_000_000,
    side_effect_lookback_ns: int = 30_000_000_000,
    max_side_effect_files: int = 1, max_network_groups: int = 3,
) -> set[str]:
    """Follow a written executable into its child and bounded network activity.

    This uses the declared file-write POI and raw graph fields only. A process
    that scans thousands of ports contributes at most one edge per /24 group.
    """
    if min(max_execution_ns, max_forward_ns, side_effect_lookback_ns,
           max_side_effect_files, max_network_groups) < 0:
        raise ValueError('forward bounds must be nonnegative')
    writes_by_process: dict[str, list[dict]] = {}
    executes_by_process: dict[str, list[dict]] = {}
    executes_by_child: dict[str, list[dict]] = {}
    forks_by_process: dict[str, list[dict]] = {}
    connects_by_process: dict[str, list[dict]] = {}
    for row in rows:
        relation = row.get('relation')
        source = row.get('src')
        if relation == 'EVENT_WRITE':
            writes_by_process.setdefault(source, []).append(row)
        elif relation == 'EVENT_EXECUTE':
            executes_by_process.setdefault(source, []).append(row)
            executes_by_child.setdefault(row.get('dst'), []).append(row)
        elif relation == 'EVENT_FORK':
            forks_by_process.setdefault(source, []).append(row)
        elif relation == 'EVENT_CONNECT':
            connects_by_process.setdefault(source, []).append(row)

    selected: set[str] = set()
    for poi in rows:
        if poi.get('is_declared_poi') is not True or poi.get('relation') != 'EVENT_WRITE':
            continue
        name = _file_basename(poi.get('dst_semantic'))
        if not name:
            continue
        start = int(poi['timestamp_ns'])
        host = poi.get('host')
        def same_host(row: dict) -> bool:
            return not host or not row.get('host') or row['host'] == host

        matching_forks = [row for row in forks_by_process.get(poi.get('src'), [])
                          if row.get('dst') and same_host(row)
                          and start <= int(row['timestamp_ns']) <= start + max_execution_ns]
        executable_children = {row['dst'] for row in matching_forks}
        candidates = [row for child in executable_children
                      for row in executes_by_child.get(child, [])
                      if same_host(row) and _process_basename(row.get('dst_semantic')) == name
                      and start <= int(row['timestamp_ns']) <= start + max_execution_ns]
        candidates += [row for row in executes_by_process.get(poi.get('src'), [])
                       if row.get('dst') and same_host(row)
                       and _process_basename(row.get('dst_semantic')) == name
                       and start <= int(row['timestamp_ns']) <= start + max_execution_ns]
        if not candidates:
            continue
        execute = min(candidates, key=lambda row: (int(row['timestamp_ns']), row['event_id']))
        selected.add(execute['event_id'])
        execute_time = int(execute['timestamp_ns'])
        forks = [row for row in matching_forks
                 if row.get('dst') == execute.get('dst') and same_host(row)
                 and start <= int(row['timestamp_ns']) <= execute_time]
        if forks:
            selected.add(max(forks, key=lambda row: (int(row['timestamp_ns']), row['event_id']))['event_id'])

        poi_directory = ntpath.dirname(str(poi.get('dst_semantic'))[5:]).casefold()
        side_effects = [row for row in writes_by_process.get(poi.get('src'), [])
                        if row.get('dst') != poi.get('dst')
                        and str(row.get('dst_semantic', '')).startswith('file:')
                        and same_host(row)
                        and start - side_effect_lookback_ns <= int(row['timestamp_ns']) <= start]
        side_effects.sort(key=lambda row: (
            ntpath.dirname(str(row['dst_semantic'])[5:]).casefold() != poi_directory,
            start - int(row['timestamp_ns']), row['event_id'],
        ))
        seen_files: set[str] = set()
        for row in side_effects if max_side_effect_files else []:
            if row.get('dst') not in seen_files:
                selected.add(row['event_id'])
                seen_files.add(row.get('dst'))
                if len(seen_files) >= max_side_effect_files:
                    break

        connects = [row for row in connects_by_process.get(execute.get('dst'), [])
                    if same_host(row) and execute_time <= int(row['timestamp_ns']) <= start + max_forward_ns
                    and _socket_destination_group(row.get('dst_semantic'))]
        connects.sort(key=lambda row: (
            int(row['timestamp_ns']), _socket_destination_port(row.get('dst_semantic')),
            row['event_id'],
        ))
        seen_groups: set[str] = set()
        for row in connects if max_network_groups else []:
            group = _socket_destination_group(row.get('dst_semantic'))
            if group not in seen_groups:
                selected.add(row['event_id'])
                seen_groups.add(group)
                if len(seen_groups) >= max_network_groups:
                    break
    return selected


def post_write_parent_connect(
    rows: list[dict], *, parent_lookback_ns: int = 60_000_000_000,
    after_ns: int = 2_000_000_000,
) -> set[str]:
    """Keep the first new socket opened by a writer or its parent after a write POI."""
    if parent_lookback_ns < 0 or after_ns < 0:
        raise ValueError('post-write bounds must be nonnegative')
    forks_by_child: dict[str, list[dict]] = {}
    connects_by_process: dict[str, list[dict]] = {}
    for row in rows:
        if row.get('relation') == 'EVENT_FORK':
            forks_by_child.setdefault(row.get('dst'), []).append(row)
        elif row.get('relation') == 'EVENT_CONNECT':
            connects_by_process.setdefault(row.get('src'), []).append(row)
    selected: set[str] = set()
    for poi in rows:
        if poi.get('is_declared_poi') is not True or poi.get('relation') != 'EVENT_WRITE':
            continue
        timestamp = int(poi['timestamp_ns'])
        host = poi.get('host')
        def same_host(row: dict) -> bool:
            return not host or not row.get('host') or row['host'] == host
        parents = [row for row in forks_by_child.get(poi.get('src'), [])
                   if same_host(row)
                   and timestamp - parent_lookback_ns <= int(row['timestamp_ns']) <= timestamp]
        parent = max(parents, key=lambda row: (int(row['timestamp_ns']), row['event_id']), default=None)
        processes = {poi.get('src')}
        if parent:
            processes.add(parent.get('src'))
        all_connects = [row for process in processes
                        for row in connects_by_process.get(process, []) if same_host(row)]
        prior_sockets = {row.get('dst') for row in all_connects
                         if timestamp - parent_lookback_ns <= int(row['timestamp_ns']) < timestamp}
        later = [row for row in all_connects if row.get('dst') not in prior_sockets
                 and timestamp < int(row['timestamp_ns']) <= timestamp + after_ns]
        if later:
            connect = min(later, key=lambda row: (int(row['timestamp_ns']), row['event_id']))
            selected.add(connect['event_id'])
            if parent and connect.get('src') == parent.get('src'):
                selected.add(parent['event_id'])
    return selected


def executable_continuations(rows: list[dict], *, max_delay_ns: int = 1_000_000_000) -> set[str]:
    """Return the earliest matching EXECUTE within the bound for each WRITE POI."""
    if max_delay_ns < 0:
        raise ValueError('max_delay_ns must be nonnegative')
    writes = [
        (row['event_id'], _file_basename(row.get('dst_semantic')), int(row['timestamp_ns']), row.get('host'))
        for row in rows
        if row.get('is_declared_poi') is True and row.get('relation') == 'EVENT_WRITE'
    ]
    executions: dict[str, list[tuple[int, str, object]]] = {}
    for row in rows:
        if row.get('relation') != 'EVENT_EXECUTE':
            continue
        basename = _file_basename(row.get('dst_semantic'))
        if basename:
            executions.setdefault(basename, []).append((int(row['timestamp_ns']), row['event_id'], row.get('host')))
    selected = set()
    for _, basename, timestamp, host in writes:
        if not basename:
            continue
        matches = (candidate for candidate in executions.get(basename, [])
                   if timestamp <= candidate[0] <= timestamp + max_delay_ns
                   and (not host or not candidate[2] or candidate[2] == host))
        earliest = min(matches, default=None)
        if earliest:
            selected.add(earliest[1])
    return selected


def adjacent_file_writes(rows: list[dict], *, max_delay_ns: int = 1_000_000_000) -> set[str]:
    """Keep writes to the identical file UUID near an already declared write POI."""
    if max_delay_ns < 0:
        raise ValueError('max_delay_ns must be nonnegative')
    poi_writes = [row for row in rows
                  if row.get('is_declared_poi') is True and row.get('relation') == 'EVENT_WRITE']
    selected = set()
    for row in rows:
        if row.get('relation') != 'EVENT_WRITE' or row.get('is_declared_poi') is True:
            continue
        for poi in poi_writes:
            if row.get('dst') == poi.get('dst') and abs(int(row['timestamp_ns']) - int(poi['timestamp_ns'])) <= max_delay_ns:
                selected.add(row['event_id'])
                break
    return selected


def network_poi_episode(
    rows: list[dict], *, lookback_ns: int = 600_000_000_000,
    after_ns: int = 1_000_000_000, max_prior_connects: int = 8,
) -> set[str]:
    """Keep nearby connections by a network POI's process and its first send."""
    if lookback_ns < 0 or after_ns < 0 or max_prior_connects < 0:
        raise ValueError('episode bounds must be nonnegative')
    poi_connects = [row for row in rows
                    if row.get('is_declared_poi') is True and row.get('relation') == 'EVENT_CONNECT']
    selected = set()
    for poi in poi_connects:
        timestamp = int(poi['timestamp_ns'])
        prior = [row for row in rows
                 if row.get('relation') == 'EVENT_CONNECT'
                 and row.get('event_id') != poi.get('event_id')
                 and row.get('src') == poi.get('src')
                 and timestamp - lookback_ns <= int(row['timestamp_ns']) <= timestamp]
        prior.sort(key=lambda row: (int(row['timestamp_ns']), row['event_id']), reverse=True)
        selected.update(row['event_id'] for row in prior[:max_prior_connects])
        sends = [row for row in rows
                 if row.get('relation') == 'EVENT_SENDTO'
                 and row.get('dst') == poi.get('dst')
                 and timestamp <= int(row['timestamp_ns']) <= timestamp + after_ns]
        if sends:
            selected.add(min(sends, key=lambda row: (int(row['timestamp_ns']), row['event_id']))['event_id'])
    return selected


def poi_bridge_continuations(
    rows: list[dict], *, local_ns: int = 1_000_000_000,
    max_bridge_span_ns: int = 600_000_000_000,
    max_socket_receives: int = 8, max_bridge_files: int = 2,
    max_reads_per_file: int = 4, max_opens_per_file: int = 2,
) -> set[str]:
    """Join CONNECT and WRITE POIs through a nearby shared file and socket replies.

    The join uses only event endpoints, timestamps, hosts, and declared POIs.
    Bounded fanout prevents a busy process from consuming the edge budget.
    """
    if min(local_ns, max_bridge_span_ns, max_socket_receives, max_bridge_files,
           max_reads_per_file, max_opens_per_file) < 0:
        raise ValueError('bridge bounds must be nonnegative')
    connects = [row for row in rows if row.get('is_declared_poi') is True
                and row.get('relation') == 'EVENT_CONNECT']
    writes = [row for row in rows if row.get('is_declared_poi') is True
              and row.get('relation') == 'EVENT_WRITE']
    if not connects or not writes:
        return set()
    receives: dict[str, list[dict]] = {}
    reads: dict[str, list[dict]] = {}
    opens: dict[str, list[dict]] = {}
    forks: dict[str, list[dict]] = {}
    for row in rows:
        relation = row.get('relation')
        if relation == 'EVENT_RECVFROM':
            receives.setdefault(row.get('src'), []).append(row)
        elif relation == 'EVENT_READ':
            reads.setdefault(row.get('dst'), []).append(row)
        elif relation == 'EVENT_OPEN':
            opens.setdefault(row.get('src'), []).append(row)
        elif relation == 'EVENT_FORK':
            forks.setdefault(row.get('src'), []).append(row)

    def same_host(row: dict, poi: dict) -> bool:
        return not row.get('host') or not poi.get('host') or row['host'] == poi['host']

    selected: set[str] = set()
    for connect in connects:
        connect_time = int(connect['timestamp_ns'])
        replies = [row for row in receives.get(connect.get('dst'), [])
                   if row.get('dst') == connect.get('src') and same_host(row, connect)
                   and connect_time <= int(row['timestamp_ns']) <= connect_time + local_ns]
        replies.sort(key=lambda row: (int(row['timestamp_ns']), row['event_id']))
        selected.update(row['event_id'] for row in replies[:max_socket_receives])
        near_forks = [row for row in forks.get(connect.get('src'), [])
                      if same_host(row, connect)
                      and abs(int(row['timestamp_ns']) - connect_time) <= local_ns]
        child_forks = {row.get('dst'): row for row in near_forks}
        candidate_processes = {connect.get('src')} | set(child_forks)
        near_opens = [row for process in candidate_processes
                      for row in opens.get(process, [])
                      if same_host(row, connect)
                      and abs(int(row['timestamp_ns']) - connect_time) <= local_ns
                      and (process == connect.get('src')
                           or int(child_forks[process]['timestamp_ns']) <= int(row['timestamp_ns']))]
        opens_by_file: dict[str, list[dict]] = {}
        for row in near_opens:
            opens_by_file.setdefault(row.get('dst'), []).append(row)
        for write in writes:
            write_time = int(write['timestamp_ns'])
            if not (connect_time <= write_time <= connect_time + max_bridge_span_ns):
                continue
            if connect.get('host') and write.get('host') and connect['host'] != write['host']:
                continue
            near_reads = [row for row in reads.get(write.get('src'), [])
                          if same_host(row, write)
                          and write_time - local_ns <= int(row['timestamp_ns']) <= write_time]
            reads_by_file: dict[str, list[dict]] = {}
            for row in near_reads:
                reads_by_file.setdefault(row.get('src'), []).append(row)
            shared = set(opens_by_file) & set(reads_by_file)
            ordered = sorted(shared, key=lambda file_id: (
                -max(int(row['timestamp_ns']) for row in reads_by_file[file_id]),
                str(file_id),
            ))
            for file_id in ordered[:max_bridge_files]:
                file_reads = sorted(reads_by_file[file_id],
                                    key=lambda row: (int(row['timestamp_ns']), row['event_id']),
                                    reverse=True)
                file_opens = sorted(opens_by_file[file_id],
                                    key=lambda row: (abs(int(row['timestamp_ns']) - connect_time), row['event_id']))
                selected.update(row['event_id'] for row in file_reads[:max_reads_per_file])
                chosen_opens = file_opens[:max_opens_per_file]
                selected.update(row['event_id'] for row in chosen_opens)
                selected.update(child_forks[row['src']]['event_id']
                                for row in chosen_opens if row.get('src') in child_forks)
    return selected


def file_poi_io_origin(
    rows: list[dict], *, before_ns: int = 60_000_000_000,
    after_ns: int = 360_000_000_000, max_read_events: int = 80,
) -> set[str]:
    """Preserve the dominant socket episode of a file WRITE POI's process.

    A one-hop process parent is allowed. This is useful when a downloaded file
    is written by a child process while its parent owns the receiving socket.
    """
    if before_ns < 0 or after_ns < 0 or max_read_events < 0:
        raise ValueError('file origin bounds must be nonnegative')
    writes = [row for row in rows if row.get('is_declared_poi') is True
              and row.get('relation') == 'EVENT_WRITE']
    if not writes:
        return set()
    forks_by_child: dict[str, list[dict]] = {}
    socket_reads_by_process: dict[str, list[dict]] = {}
    connects_by_socket: dict[str, list[dict]] = {}
    for row in rows:
        relation = row.get('relation')
        if relation == 'EVENT_FORK':
            forks_by_child.setdefault(row.get('dst'), []).append(row)
        elif relation in ('EVENT_READ', 'EVENT_RECVFROM') and (
            row.get('src_type') == 'socket'
            or str(row.get('src_semantic', '')).startswith('socket:')
        ):
            socket_reads_by_process.setdefault(row.get('dst'), []).append(row)
        elif relation == 'EVENT_CONNECT':
            connects_by_socket.setdefault(row.get('dst'), []).append(row)

    selected: set[str] = set()
    for write in writes:
        timestamp = int(write['timestamp_ns'])
        host = write.get('host')
        def same_host(row: dict) -> bool:
            return not host or not row.get('host') or row['host'] == host
        parents = [row for row in forks_by_child.get(write.get('src'), [])
                   if same_host(row)
                   and timestamp - before_ns <= int(row['timestamp_ns']) <= timestamp]
        parent_edge = max(parents, key=lambda row: (int(row['timestamp_ns']), row['event_id']), default=None)
        processes = {write.get('src')}
        if parent_edge:
            processes.add(parent_edge.get('src'))
        socket_events: dict[str, list[dict]] = {}
        for process in processes:
            for row in socket_reads_by_process.get(process, []):
                if same_host(row) and timestamp - before_ns <= int(row['timestamp_ns']) <= timestamp + after_ns:
                    socket_events.setdefault(row.get('src'), []).append(row)
        if not socket_events:
            continue
        socket_id = max(socket_events, key=lambda key: (
            sum(max(0, int(row.get('data_size') or 0)) for row in socket_events[key]),
            len(socket_events[key]), str(key),
        ))
        chosen_reads = sorted(socket_events[socket_id], key=lambda row: (
            -max(0, int(row.get('data_size') or 0)), int(row['timestamp_ns']), row['event_id'],
        ))[:max_read_events]
        if not chosen_reads:
            continue
        selected.update(row['event_id'] for row in chosen_reads)
        if parent_edge:
            selected.add(parent_edge['event_id'])
        connects = [row for row in connects_by_socket.get(socket_id, [])
                    if row.get('src') in processes and same_host(row)
                    and timestamp - before_ns <= int(row['timestamp_ns']) <= timestamp + after_ns]
        if connects:
            selected.add(min(connects, key=lambda row: (
                abs(int(row['timestamp_ns']) - timestamp), row['event_id'],
            ))['event_id'])
    return selected


def command_line_executions(
    poi_rows: list[dict], raw_lines: Iterable[str], *,
    max_delay_ns: int = 60_000_000_000, max_matches_per_poi: int = 2,
) -> set[str]:
    """Resolve same-host raw EXECUTE command lines mentioning a POI file."""
    if max_delay_ns < 0 or max_matches_per_poi < 0:
        raise ValueError('command-line bounds must be nonnegative')
    anchors = []
    for row in poi_rows:
        if row.get('is_declared_poi') is not True or row.get('relation') not in ('EVENT_OPEN', 'EVENT_WRITE'):
            continue
        basename = _file_basename(row.get('dst_semantic'))
        if basename:
            pattern = re.compile(r'(?<![\w.-])' + re.escape(basename) + r'(?![\w.-])', re.IGNORECASE)
            anchors.append((basename, pattern, int(row['timestamp_ns']), row.get('host')))
    if not anchors:
        return set()
    matches: list[list[tuple[int, str]]] = [[] for _ in anchors]
    for line in raw_lines:
        if not any(basename in line.casefold() for basename, _, _, _ in anchors):
            continue
        record = json.loads(line)
        datum = record.get('datum', {})
        event = next((value for key, value in datum.items() if key.endswith('.Event')), None)
        if not isinstance(event, dict) or event.get('type') != 'EVENT_EXECUTE':
            continue
        command = (event.get('properties') or {}).get('map', {}).get('cmdLine')
        if not isinstance(command, str):
            continue
        timestamp = event.get('timestampNanos')
        if isinstance(timestamp, dict):
            timestamp = timestamp.get('long')
        if not isinstance(timestamp, int):
            continue
        for index, (_, pattern, poi_time, host) in enumerate(anchors):
            if poi_time <= timestamp <= poi_time + max_delay_ns and (
                not host or not event.get('hostId') or event['hostId'] == host
            ) and pattern.search(command):
                matches[index].append((timestamp, event['uuid']))
    return {event_id for group in matches
            for _, event_id in sorted(group)[:max_matches_per_poi]}
