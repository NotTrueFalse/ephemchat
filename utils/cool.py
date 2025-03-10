import secrets
def to_humain_readable(size:int)->str:
    for unit in ['Octets', 'Ko', 'Mo', 'Go', 'To']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"

def generate_address(length:int)->str:
    bytes = secrets.token_bytes(length)
    allowed = (48,57),(64,64+26),(97,97+25)#0-9,A-Z,a-z+@
    allowed = [list(range(i,j+1)) for i,j in allowed]
    allowed = [chr(i) for i in sum(allowed,[])]
    address = ""
    for byte in bytes:
        address += allowed[byte%len(allowed)]
    return address