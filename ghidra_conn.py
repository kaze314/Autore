import httpx
import asyncio

GHIDRA_SERVER = "http://127.0.0.1:8089"

class GhidraConn:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def close(self):
        await self.client.aclose()

    async def update_ghidra(self):
        raw = await self.client.get(GHIDRA_SERVER + "/schema")
        print(raw.text[:500])

    async def _paginate(self, endpoint, page=2000):
        args = {}
        offset = 0

        while True:
            args.update({"offset": offset, "limit": page})
            text = (await self.client.get(GHIDRA_SERVER + endpoint, params=args)).text
            if not text or text.startswith("__ERROR__") or not text.strip():
                return
            yield text

            n = len([ln for ln in text.splitlines() if ln.strip()])
            if n < page:
                return 
            
            offset += page
            
    async def get_functions(self):
        raw = await self.client.get(GHIDRA_SERVER + "/list_functions")
        return GhidraConn._parse_function_list(raw.text)

    async def get_strings(self):
        strings = []
        async for text in self._paginate("/list_strings"):
            items = GhidraConn._parse_strings(text)
            strings.extend(items)

        return strings

    async def get_imports(self):
        imports = []
        async for text in self._paginate("/list_imports"):
            items = GhidraConn._parse_imports(text)
            imports.extend(items)

        return imports

    # ('0x18030c830', 'some string')
    def _parse_strings(text):
        out = []
        for line in (text or "").splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            addr, _, rest = line.partition(":")
            addr = addr.strip()
            rest = rest.strip()
            if len(rest) >= 2 and rest[0] == '"' and rest.endswith('"'):
                out.append(("0x" + addr.lower(), rest[1:-1]))
        return out

    def _parse_imports(text):
        names = set()
        for line in text.split('{"name":"'):
            names.add(line.split("\"")[0])
        return names

    #[{name, address}]
    def _parse_function_list(text):
        funcs = []

        for line in text.splitlines():
            parts = line.split(" ")
            name = parts[0]
            address = parts[-1]

            funcs.append({'name': name, 'address': '0x' + address})

        return funcs

    async def decompile_func(self, function_address):
        params = {
            'address': function_address,
        }
        raw = await self.client.get(GHIDRA_SERVER + "/decompile_function", params=params)
        return raw.text
    
    async def batch_rename(self, function_address, function_name, parameter_renames={}, local_renames={}):
        params = {
            'function_address': function_address,
            'function_name': function_name,
            'parameter_renames': parameter_renames,
            'local_renames': local_renames
        }
        raw = await self.client.post(GHIDRA_SERVER + "/batch_rename_function_components", json=params)
        return raw.json()



async def test():
    conn = GhidraConn()

    # test strings
    strings = await conn.get_strings()
    print(strings[0])
    print(len(strings))

    # test imports
    imports = await conn.get_imports()
    print(imports[:50])
    print(len(imports))

    # test functions
    funcs = await conn.get_functions()
    print(funcs[:50])
    print(len(funcs))

    r = await conn.batch_rename('0x180001000', 'FUN_perp')
    print(r)

    
    r = await conn.decompile_func('0x180001000')
    print(r)
    
    await conn.close()

if __name__ == "__main__":
    asyncio.run(test())



