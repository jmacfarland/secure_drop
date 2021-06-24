#! /usr/bin/env python3
import asyncio
from peer import Peer

async def main():
    p = Peer("localhost",10001)
    message = await p.receive()
    print("received '{0}'").format(message)

if __name__ == "__main__":
    asyncio.run(main())
