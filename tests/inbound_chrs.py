#!/usr/bin/env python3
"""Toss a synthetic Type-2+ PKT and check JAM and forwarded packet bytes."""
import argparse
from datetime import datetime
from pathlib import Path
import struct
import subprocess
import tempfile


AREA = 'CHARSET.TEST'
MSGID = b'2:10/1 12345678'
REPLY = b'2:10/9 87654321'
EXTRA = b'X-TEST: preserved'


def packet(names, subject, body, labels):
    date = datetime.now()
    header = bytearray(58)
    struct.pack_into('<12H', header, 0, 1, 2, date.year, date.month - 1, date.day,
                     date.hour, date.minute, date.second, 0, 2, 10, 10)
    header[26:33] = b'fixture'
    struct.pack_into('<HH', header, 34, 2, 2)
    struct.pack_into('>H', header, 40, 1)  # Byte-swapped capability word.
    struct.pack_into('<HHH', header, 44, 1, 2, 2)
    month = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')[date.month - 1]
    date_text = f'{date:%d} {month} {date:%y  %H:%M:%S}'.encode('ascii')
    assert len(date_text) == 19
    lines = [b'AREA:' + AREA.encode('ascii'), b'\x01MSGID: ' + MSGID]
    lines += [b'\x01' + label for label in labels]
    lines += [b'\x01REPLY: ' + REPLY, b'\x01' + EXTRA, body,
              b' * Origin: Charset fixture (2:10/1)', b'SEEN-BY: 10/1', b'\x01PATH: 10/1']
    text = b'\r'.join(lines) + b'\r'
    message = struct.pack('<7H', 2, 1, 2, 10, 10, 0, 0)
    return header + message + b'\0'.join((date_text, *names, subject, text)) + b'\0\0\0', text


def read_forwarded(root):
    for file in (root / 'outbound').rglob('*'):
        if not file.is_file():
            continue
        data = file.read_bytes()
        if len(data) < 60 or struct.unpack_from('<H', data, 18)[0] != 2:
            continue
        if struct.unpack_from('<H', data, 2)[0] != 3:
            continue
        assert struct.unpack_from('<H', data, 58)[0] == 2
        fields = data[72:].split(b'\0', 5)
        assert fields[-1] == b'\0\0'
        return fields[1:5]
    raise AssertionError('No forwarded PKT for 2:10/3')


def read_jam(base):
    index = base.with_suffix('.jdx').read_bytes()
    header = base.with_suffix('.jhr').read_bytes()
    text = base.with_suffix('.jdt').read_bytes()
    assert len(index) == 8
    offset = struct.unpack_from('<I', index, 4)[0]
    assert header[offset:offset + 4] == b'JAM\0'
    subfield_size = struct.unpack_from('<I', header, offset + 8)[0]
    text_offset, text_size = struct.unpack_from('<II', header, offset + 60)
    end = offset + 76 + subfield_size
    fields = {}
    offset += 76
    while offset < end:
        low, high, size = struct.unpack_from('<HHI', header, offset)
        offset += 8
        assert high == 0 and offset + size <= end
        fields.setdefault(low, []).append(header[offset:offset + size])
        offset += size
    assert offset == end
    return fields, text[text_offset:text_offset + text_size]


def configure(root, annotation, table, recode, passthrough):
    config = ['Name Charset fixture', 'Sysop Test', 'Location Local', 'Address 2:10/2']
    for keyword, folder in (
        ('Inbound', 'inbound'), ('ProtInbound', 'protected'), ('Outbound', 'outbound'),
        ('TempInbound', 'tmpin'), ('TempOutbound', 'tmpout'), ('LogFileDir', 'logs'),
        ('DupeHistoryDir', 'dupes'), ('NodelistDir', 'nodelist'), ('MsgBaseDir', 'jam'),
    ):
        (root / folder).mkdir()
        config.append(f'{keyword} {folder}')
    table_path = root / 'intab'
    table_path.write_text(annotation + ''.join(f'0x{source:02X} 0x{target:02X}\n'
                                               for source, target in sorted(table.items())),
                          encoding='ascii')
    config += ['Intab intab', f'RecodeMsgBase {"on" if recode else "off"}',
               'Link Sender', 'AKA 2:10/1', 'OurAKA 2:10/2', 'Password fixture',
               'Link Transit', 'AKA 2:10/3', 'OurAKA 2:10/2', 'Password fixture']
    area_base = 'passthrough' if passthrough else 'jam/echo -b JAM'
    config.append(f'EchoArea {AREA} {area_base} -dupeCheck off 2:10/1 2:10/3')
    for keyword, name in (('NetmailArea', 'netmail'), ('BadArea', 'bad'), ('DupeArea', 'dupe')):
        config.append(f'{keyword} {name} jam/{name} -b JAM')
    cfg = root / 'hpt.cfg'
    cfg.write_text('\n'.join(config) + '\n', encoding='ascii')
    return cfg


def check(hpt, root, source, target, labels, expected_labels, annotation, recode=True, passthrough=False,
          extra_table=None):
    values = ('Zoë', 'André', 'Café déjà vu', 'Une pièce très chère') if source == 'cp437' else (
        'Наталья', 'Сергей', 'Проверка Ёё', 'Читаем письмо: ёлка и Ёжик')
    original = [value.encode(source) for value in values]
    translated = [value.encode(target) for value in values]
    table = {old: new for before, after in zip(original, translated) for old, new in zip(before, after) if old != new}
    table.update(extra_table or {})
    cfg = configure(root, annotation, table, recode, passthrough)
    data, wire_text = packet(original[:2], original[2], original[3], labels)
    (root / 'protected' / 'fixture.pkt').write_bytes(data)
    result = subprocess.run([str(hpt), '-c', str(cfg), 'toss'], cwd=root,
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    forwarded = read_forwarded(root)
    assert forwarded[:3] == original[:3]
    # HPT updates routing lines on transit. Everything before them stays on the wire.
    assert forwarded[3].split(b'\rSEEN-BY:', 1)[0] == wire_text.split(b'\rSEEN-BY:', 1)[0]
    base = root / 'jam' / 'echo'
    if passthrough:
        assert not base.with_suffix('.jdx').exists()
        return
    fields, body = read_jam(base)
    local = translated if recode else original
    assert [fields[3], fields[2], fields[6]] == [[value] for value in local[:3]]
    assert body.startswith(local[3] + b'\r')
    assert fields[4] == [MSGID] and fields[5] == [REPLY]
    kludges = fields.get(2000, [])
    assert [value for value in kludges if value.upper().startswith(b'CHRS:')] == expected_labels, kludges
    assert EXTRA in kludges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('hpt', type=Path, help='Path to the HPT executable to test')
    hpt = parser.parse_args().hpt.resolve(strict=True)
    cp866, koi8 = b'CHRS: CP866 2', b'CHRS: KOI8-R 2'
    annotated = '# CHRS: CP866 2 -> KOI8-R 2\n'
    cases = [
        ('jam-and-transit', [cp866], [koi8], annotated, {}),
        ('equivalent-duplicates', [cp866, b'chrs: cp866\t2 '], [koi8], annotated, {}),
        ('no-annotation', [cp866], [cp866], '', {}),
        ('missing-chrs', [], [], annotated, {}),
        ('conflicting-chrs', [cp866, b'CHRS: UTF-8 4'], [cp866, b'CHRS: UTF-8 4'], annotated, {}),
        ('different-source', [koi8], [koi8], annotated, {}),
        ('invalid-annotation', [cp866], [cp866], annotated.rstrip() + ' junk\n', {}),
        ('ascii-changing-table', [cp866], [cp866], annotated, {'extra_table': {0x7e: 0x7d}}),
        ('recode-off', [cp866], [cp866], annotated, {'recode': False}),
        ('passthrough', [cp866], [], annotated, {'passthrough': True}),
    ]
    with tempfile.TemporaryDirectory(prefix='hpt-inbound-chrs-') as directory:
        for name, labels, expected, annotation, options in cases:
            root = Path(directory) / name
            root.mkdir()
            try:
                check(hpt, root, 'cp866', 'koi8-r', labels, expected, annotation, **options)
            except AssertionError as error:
                raise AssertionError(f'{name}: {error}') from error
        root = Path(directory) / 'another-charset'
        root.mkdir()
        check(hpt, root, 'cp437', 'latin-1', [b'CHRS: CP437 2'], [b'CHRS: LATIN-1 2'],
              '# CHRS: CP437 2 -> LATIN-1 2\n')
    print(f'Passed {len(cases) + 1} synthetic PKT cases')


if __name__ == '__main__':
    main()
