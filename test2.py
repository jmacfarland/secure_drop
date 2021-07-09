#! /usr/bin/env python3
import asyncio
from btpeer import BTPeer

def main():
    p = BTPeer(5,10000,myid="two@two.com")
    p.addpeer("one",'localhost',10001)
    p.mainloop()


if __name__ == "__main__":
    main()
