import json

from tc_pruning.poi_semantic_continuation import (
    adjacent_file_writes, command_line_executions, executable_continuations,
    network_poi_episode, poi_bridge_continuations, file_poi_io_origin,
    forward_file_execution,
    post_write_parent_connect,
)


def test_matches_unique_execution_of_written_file_with_windows_basename():
    poi = {'event_id': 'write', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
           'dst_semantic': r'file:\Device\HarddiskVolume2\add-on\hJauWl01', 'timestamp_ns': 100}
    rows = [poi,
            {'event_id': 'execute', 'relation': 'EVENT_EXECUTE', 'dst_semantic': 'file:hJauWl01', 'timestamp_ns': 110},
            {'event_id': 'other', 'relation': 'EVENT_EXECUTE', 'dst_semantic': 'file:unrelated', 'timestamp_ns': 111}]
    assert executable_continuations(rows, max_delay_ns=20) == {'execute'}


def test_excludes_events_before_poi_and_after_window():
    rows = [
        {'event_id': 'write', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'dst_semantic': r'file:C:\drop\implant.exe', 'timestamp_ns': 100},
        {'event_id': 'before', 'relation': 'EVENT_EXECUTE', 'dst_semantic': 'file:implant.exe', 'timestamp_ns': 99},
        {'event_id': 'late', 'relation': 'EVENT_EXECUTE', 'dst_semantic': 'file:implant.exe', 'timestamp_ns': 122},
    ]
    assert executable_continuations(rows, max_delay_ns=20) == set()


def test_file_execution_continuation_stays_on_same_host():
    rows = [
        {'event_id': 'write', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'dst_semantic': 'file:C:\\drop\\implant.exe', 'timestamp_ns': 100, 'host': 'one'},
        {'event_id': 'other-host', 'relation': 'EVENT_EXECUTE',
         'dst_semantic': 'file:implant.exe', 'timestamp_ns': 101, 'host': 'two'},
        {'event_id': 'same-host', 'relation': 'EVENT_EXECUTE',
         'dst_semantic': 'file:implant.exe', 'timestamp_ns': 102, 'host': 'one'},
    ]
    assert executable_continuations(rows, max_delay_ns=20) == {'same-host'}


def test_only_first_execution_per_poi_and_no_network_poi_expansion():
    rows = [
        {'event_id': 'network', 'is_declared_poi': True, 'relation': 'EVENT_CONNECT',
         'dst_semantic': 'socket:implant.exe', 'timestamp_ns': 90},
        {'event_id': 'write', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'dst_semantic': r'file:C:\drop\implant.exe', 'timestamp_ns': 100},
        {'event_id': 'second', 'relation': 'EVENT_EXECUTE', 'dst_semantic': 'file:implant.exe', 'timestamp_ns': 120},
        {'event_id': 'first', 'relation': 'EVENT_EXECUTE', 'dst_semantic': 'file:implant.exe', 'timestamp_ns': 110},
    ]
    assert executable_continuations(rows, max_delay_ns=20) == {'first'}


def test_preserves_other_writes_to_the_poi_file_in_same_second():
    rows = [
        {'event_id': 'poi', 'is_declared_poi': True, 'relation': 'EVENT_WRITE', 'dst': 'file-uuid', 'timestamp_ns': 100},
        {'event_id': 'earlier', 'relation': 'EVENT_WRITE', 'dst': 'file-uuid', 'timestamp_ns': 90},
        {'event_id': 'later', 'relation': 'EVENT_WRITE', 'dst': 'file-uuid', 'timestamp_ns': 110},
        {'event_id': 'other', 'relation': 'EVENT_WRITE', 'dst': 'other-uuid', 'timestamp_ns': 95},
        {'event_id': 'old', 'relation': 'EVENT_WRITE', 'dst': 'file-uuid', 'timestamp_ns': 70},
    ]
    assert adjacent_file_writes(rows, max_delay_ns=15) == {'earlier', 'later'}


def test_network_poi_episode_bounds_same_process_connects_and_first_send():
    rows = [
        {'event_id': 'poi', 'is_declared_poi': True, 'relation': 'EVENT_CONNECT',
         'src': 'proc', 'dst': 'socket', 'timestamp_ns': 100},
        {'event_id': 'old', 'relation': 'EVENT_CONNECT', 'src': 'proc', 'dst': 'old-socket', 'timestamp_ns': 70},
        {'event_id': 'a', 'relation': 'EVENT_CONNECT', 'src': 'proc', 'dst': 'a-socket', 'timestamp_ns': 90},
        {'event_id': 'b', 'relation': 'EVENT_CONNECT', 'src': 'proc', 'dst': 'b-socket', 'timestamp_ns': 95},
        {'event_id': 'other-process', 'relation': 'EVENT_CONNECT', 'src': 'other', 'dst': 'c-socket', 'timestamp_ns': 99},
        {'event_id': 'send-first', 'relation': 'EVENT_SENDTO', 'src': 'proc', 'dst': 'socket', 'timestamp_ns': 101},
        {'event_id': 'send-second', 'relation': 'EVENT_SENDTO', 'src': 'proc', 'dst': 'socket', 'timestamp_ns': 102},
    ]
    assert network_poi_episode(rows, lookback_ns=20, after_ns=10, max_prior_connects=2) == {'a', 'b', 'send-first'}


def test_raw_cdm_command_line_continuation_matches_poi_filename_without_external_alert():
    poi = [{'event_id': 'open', 'is_declared_poi': True, 'relation': 'EVENT_OPEN',
            'dst_semantic': 'file:/home/admin/Documents/tcexec', 'timestamp_ns': 100, 'host': 'host-one'}]

    def raw(event_id, cmdline, timestamp, host='host-one'):
        return json.dumps({'datum': {'com.bbn.tc.schema.avro.cdm18.Event': {
            'uuid': event_id, 'type': 'EVENT_EXECUTE', 'timestampNanos': timestamp,
            'hostId': host, 'properties': {'map': {'cmdLine': cmdline}},
        }}}) + '\n'

    lines = [raw('chmod', 'chmod +x tcexec', 110), raw('run', './tcexec', 120),
             raw('wrong-name', './tcexec-old', 121), raw('wrong-host', './tcexec', 122, 'host-two'),
             raw('late', './tcexec', 200)]
    assert command_line_executions(poi, lines, max_delay_ns=30) == {'chmod', 'run'}


def test_two_poi_bridge_preserves_socket_replies_and_shared_file_dependencies():
    rows = [
        {'event_id': 'connect', 'is_declared_poi': True, 'relation': 'EVENT_CONNECT',
         'src': 'net-proc', 'dst': 'socket', 'timestamp_ns': 100, 'host': 'h'},
        {'event_id': 'write', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'src': 'writer', 'dst': 'payload', 'timestamp_ns': 300, 'host': 'h'},
        {'event_id': 'reply-1', 'relation': 'EVENT_RECVFROM', 'src': 'socket',
         'dst': 'net-proc', 'timestamp_ns': 101, 'host': 'h'},
        {'event_id': 'reply-2', 'relation': 'EVENT_RECVFROM', 'src': 'socket',
         'dst': 'net-proc', 'timestamp_ns': 102, 'host': 'h'},
        {'event_id': 'open', 'relation': 'EVENT_OPEN', 'src': 'net-proc',
         'dst': 'shared-file', 'timestamp_ns': 99, 'host': 'h'},
        {'event_id': 'read', 'relation': 'EVENT_READ', 'src': 'shared-file',
         'dst': 'writer', 'timestamp_ns': 299, 'host': 'h'},
        {'event_id': 'wrong-file', 'relation': 'EVENT_READ', 'src': 'other-file',
         'dst': 'writer', 'timestamp_ns': 299, 'host': 'h'},
        {'event_id': 'wrong-host', 'relation': 'EVENT_RECVFROM', 'src': 'socket',
         'dst': 'net-proc', 'timestamp_ns': 103, 'host': 'other'},
        {'event_id': 'late-reply', 'relation': 'EVENT_RECVFROM', 'src': 'socket',
         'dst': 'net-proc', 'timestamp_ns': 120, 'host': 'h'},
    ]
    assert poi_bridge_continuations(rows, local_ns=5, max_bridge_span_ns=250) == {
        'reply-1', 'reply-2', 'open', 'read',
    }


def test_two_poi_bridge_follows_one_nearby_process_fork():
    rows = [
        {'event_id': 'connect', 'is_declared_poi': True, 'relation': 'EVENT_CONNECT',
         'src': 'net-proc', 'dst': 'socket', 'timestamp_ns': 100, 'host': 'h'},
        {'event_id': 'write', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'src': 'writer', 'dst': 'payload', 'timestamp_ns': 300, 'host': 'h'},
        {'event_id': 'fork', 'relation': 'EVENT_FORK', 'src': 'net-proc',
         'dst': 'child-proc', 'timestamp_ns': 98, 'host': 'h'},
        {'event_id': 'open', 'relation': 'EVENT_OPEN', 'src': 'child-proc',
         'dst': 'shared-file', 'timestamp_ns': 99, 'host': 'h'},
        {'event_id': 'read', 'relation': 'EVENT_READ', 'src': 'shared-file',
         'dst': 'writer', 'timestamp_ns': 299, 'host': 'h'},
        {'event_id': 'distant-fork', 'relation': 'EVENT_FORK', 'src': 'net-proc',
         'dst': 'other-child', 'timestamp_ns': 70, 'host': 'h'},
        {'event_id': 'unjoined-open', 'relation': 'EVENT_OPEN', 'src': 'other-child',
         'dst': 'other-file', 'timestamp_ns': 99, 'host': 'h'},
    ]
    assert poi_bridge_continuations(rows, local_ns=5, max_bridge_span_ns=250) == {
        'fork', 'open', 'read',
    }


def test_file_poi_origin_uses_nearby_parent_and_largest_socket_episode():
    rows = [
        {'event_id': 'poi', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'src': 'writer', 'dst': 'payload', 'timestamp_ns': 100, 'host': 'h'},
        {'event_id': 'lineage', 'relation': 'EVENT_FORK', 'src': 'parent',
         'dst': 'writer', 'timestamp_ns': 90, 'host': 'h'},
        {'event_id': 'connect', 'relation': 'EVENT_CONNECT', 'src': 'parent',
         'dst': 'large-socket', 'timestamp_ns': 91, 'host': 'h'},
        {'event_id': 'read-1', 'relation': 'EVENT_RECVFROM', 'src': 'large-socket',
         'src_type': 'socket', 'dst': 'parent', 'timestamp_ns': 95,
         'data_size': 12, 'host': 'h'},
        {'event_id': 'read-2', 'relation': 'EVENT_READ', 'src': 'large-socket',
         'src_type': 'socket', 'dst': 'writer', 'timestamp_ns': 105,
         'data_size': 8, 'host': 'h'},
        {'event_id': 'small', 'relation': 'EVENT_READ', 'src': 'small-socket',
         'src_type': 'socket', 'dst': 'writer', 'timestamp_ns': 102,
         'data_size': 2, 'host': 'h'},
        {'event_id': 'file-read', 'relation': 'EVENT_READ', 'src': 'file',
         'src_type': 'file', 'dst': 'writer', 'timestamp_ns': 99,
         'data_size': 1000, 'host': 'h'},
    ]
    assert file_poi_io_origin(rows, before_ns=20, after_ns=20) == {
        'lineage', 'connect', 'read-1', 'read-2',
    }


def test_forward_file_execution_keeps_payload_run_and_bounded_network_stages():
    rows = [
        {'event_id': 'poi', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'src': 'writer', 'dst': 'payload', 'dst_semantic': 'file:/tmp/tcexec',
         'timestamp_ns': 100, 'host': 'h'},
        {'event_id': 'side-effect', 'relation': 'EVENT_WRITE', 'src': 'writer',
         'dst': 'other', 'dst_semantic': 'file:/tmp/tcexfil', 'timestamp_ns': 90, 'host': 'h'},
        {'event_id': 'nearby-debug', 'relation': 'EVENT_WRITE', 'src': 'writer',
         'dst': 'debug', 'dst_semantic': 'file:/home/user/.debug', 'timestamp_ns': 99, 'host': 'h'},
        {'event_id': 'fork', 'relation': 'EVENT_FORK', 'src': 'writer',
         'dst': 'child', 'timestamp_ns': 101, 'host': 'h'},
        {'event_id': 'execute', 'relation': 'EVENT_EXECUTE', 'src': 'older-process-version',
         'dst': 'child', 'dst_semantic': 'process:tcexec', 'timestamp_ns': 101, 'host': 'h'},
        {'event_id': 'c2', 'relation': 'EVENT_CONNECT', 'src': 'child',
         'dst_semantic': 'socket:162.66.239.75:80', 'timestamp_ns': 102, 'host': 'h'},
        {'event_id': 'scan', 'relation': 'EVENT_CONNECT', 'src': 'child',
         'dst_semantic': 'socket:128.55.12.55:22', 'timestamp_ns': 103, 'host': 'h'},
        {'event_id': 'scan-duplicate', 'relation': 'EVENT_CONNECT', 'src': 'child',
         'dst_semantic': 'socket:128.55.12.55:23', 'timestamp_ns': 104, 'host': 'h'},
        {'event_id': 'shell', 'relation': 'EVENT_CONNECT', 'src': 'child',
         'dst_semantic': 'socket:103.12.253.24:80', 'timestamp_ns': 105, 'host': 'h'},
        {'event_id': 'late', 'relation': 'EVENT_CONNECT', 'src': 'child',
         'dst_semantic': 'socket:207.103.191.4:80', 'timestamp_ns': 150, 'host': 'h'},
        {'event_id': 'other-host', 'relation': 'EVENT_CONNECT', 'src': 'child',
         'dst_semantic': 'socket:8.8.8.8:80', 'timestamp_ns': 106, 'host': 'other'},
    ]
    assert forward_file_execution(rows, max_execution_ns=10, max_forward_ns=20,
                                  side_effect_lookback_ns=20,
                                  max_side_effect_files=1) == {
        'side-effect', 'fork', 'execute', 'c2', 'scan', 'shell',
    }


def test_forward_file_execution_requires_matching_execution_before_side_effects():
    rows = [
        {'event_id': 'poi', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'src': 'writer', 'dst': 'payload', 'dst_semantic': 'file:/tmp/payload',
         'timestamp_ns': 100, 'host': 'h'},
        {'event_id': 'unrelated-write', 'relation': 'EVENT_WRITE', 'src': 'writer',
         'dst': 'other', 'dst_semantic': 'file:/tmp/other', 'timestamp_ns': 90, 'host': 'h'},
    ]
    assert forward_file_execution(rows) == set()


def test_post_write_parent_connect_selects_new_socket_after_download():
    rows = [
        {'event_id': 'poi', 'is_declared_poi': True, 'relation': 'EVENT_WRITE',
         'src': 'writer', 'timestamp_ns': 100, 'host': 'h'},
        {'event_id': 'fork', 'relation': 'EVENT_FORK', 'src': 'parent',
         'dst': 'writer', 'timestamp_ns': 90, 'host': 'h'},
        {'event_id': 'download', 'relation': 'EVENT_CONNECT', 'src': 'parent',
         'dst': 'download-socket', 'timestamp_ns': 95, 'host': 'h'},
        {'event_id': 'same-socket', 'relation': 'EVENT_CONNECT', 'src': 'parent',
         'dst': 'download-socket', 'timestamp_ns': 101, 'host': 'h'},
        {'event_id': 'c2', 'relation': 'EVENT_CONNECT', 'src': 'parent',
         'dst': 'c2-socket', 'timestamp_ns': 102, 'host': 'h'},
        {'event_id': 'later', 'relation': 'EVENT_CONNECT', 'src': 'parent',
         'dst': 'later-socket', 'timestamp_ns': 103, 'host': 'h'},
        {'event_id': 'other-host', 'relation': 'EVENT_CONNECT', 'src': 'parent',
         'dst': 'wrong-host', 'timestamp_ns': 101, 'host': 'elsewhere'},
    ]
    assert post_write_parent_connect(rows, parent_lookback_ns=20,
                                     after_ns=10) == {'fork', 'c2'}
