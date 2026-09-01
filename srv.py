import asyncio
from server.cfg import H, P
from server.handler import handle
from server.http import run as http_run

#запуск
async def main():
    http_run()
    s=await asyncio.start_server(handle, H, P)
    print(f"up {H}:{P}")
    async with s:
        await s.serve_forever()

if __name__=="__main__":
    asyncio.run(main())
