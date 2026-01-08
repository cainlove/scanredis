import asyncio
import argparse
import ipaddress
from typing import List, Dict, Tuple


def parse_targets(s: str) -> List[str]:
    s = s.strip()
    if "-" in s and "/" not in s:
        a, b = s.split("-", 1)
        a = a.strip()
        b = b.strip()
        start = ipaddress.ip_address(a)
        end = ipaddress.ip_address(b)
        ips = []
        cur = int(start)
        last = int(end)
        if cur > last:
            cur, last = last, cur
        for n in range(cur, last + 1):
            ips.append(str(ipaddress.ip_address(n)))
        return ips
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            return [str(ip) for ip in net.hosts()]
        ipaddress.ip_address(s)
        return [s]
    except ValueError:
        raise argparse.ArgumentTypeError("非法的IP或网段格式")


async def read_line(reader: asyncio.StreamReader, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.readline(), timeout=timeout)


async def auth_with_passwords(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, passwords: List[str], timeout: float) -> Tuple[bool, str]:
    for pw in passwords:
        cmd = f"*2\r\n$4\r\nAUTH\r\n${len(pw)}\r\n{pw}\r\n".encode()
        writer.write(cmd)
        await writer.drain()
        line = await read_line(reader, timeout)
        if line and line.startswith(b'+') and b'OK' in line.upper():
            return True, pw
        cmd3 = f"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n${len(pw)}\r\n{pw}\r\n".encode()
        writer.write(cmd3)
        await writer.drain()
        line2 = await read_line(reader, timeout)
        if line2 and line2.startswith(b'+') and b'OK' in line2.upper():
            return True, pw
    return False, ""


async def detect_redis(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float, passwords: List[str]) -> Tuple[bool, bool, str, bool, str]:
    try:
        writer.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n")
        await writer.drain()
        line = await read_line(reader, timeout)
        if not line:
            return False, False, "", False, ""
        if line.startswith(b'-'):
            msg = line.decode(errors="ignore")
            if "NOAUTH" in msg.upper():
                if passwords:
                    ok, used = await auth_with_passwords(reader, writer, passwords, timeout)
                    if ok:
                        writer.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n")
                        await writer.drain()
                        linei = await read_line(reader, timeout)
                        if linei and linei.startswith(b'$'):
                            try:
                                length = int(linei[1:].strip())
                            except Exception:
                                return True, True, "", True, used
                            data = await asyncio.wait_for(reader.readexactly(length + 2), timeout=timeout)
                            content = data[:-2].decode(errors="ignore")
                            ver = ""
                            for ln in content.splitlines():
                                if ln.lower().startswith("redis_version:"):
                                    ver = ln.split(":", 1)[1].strip()
                                    break
                            return True, True, ver, True, used
                        return True, True, "", True, used
                return True, True, "", False, ""
            return False, False, "", False, ""
        if line.startswith(b'$'):
            try:
                length = int(line[1:].strip())
            except Exception:
                return False, False, "", False, ""
            data = await asyncio.wait_for(reader.readexactly(length + 2), timeout=timeout)
            content = data[:-2].decode(errors="ignore")
            ver = ""
            for ln in content.splitlines():
                if ln.lower().startswith("redis_version:"):
                    ver = ln.split(":", 1)[1].strip()
                    break
            return True, False, ver, False, ""
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        line2 = await read_line(reader, timeout)
        if line2 and line2.startswith(b'+') and b'PONG' in line2.upper():
            return True, False, "", False, ""
        if line2 and line2.startswith(b'-') and b'NOAUTH' in line2.upper():
            if passwords:
                ok, used = await auth_with_passwords(reader, writer, passwords, timeout)
                if ok:
                    writer.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n")
                    await writer.drain()
                    linei = await read_line(reader, timeout)
                    if linei and linei.startswith(b'$'):
                        try:
                            length = int(linei[1:].strip())
                        except Exception:
                            return True, True, "", True, used
                        data = await asyncio.wait_for(reader.readexactly(length + 2), timeout=timeout)
                        content = data[:-2].decode(errors="ignore")
                        ver = ""
                        for ln in content.splitlines():
                            if ln.lower().startswith("redis_version:"):
                                ver = ln.split(":", 1)[1].strip()
                                break
                        return True, True, ver, True, used
                    return True, True, "", True, used
            return True, True, "", False, ""
        return False, False, "", False, ""
    except Exception:
        return False, False, "", False, ""


async def scan_one(ip: str, port: int, timeout: float, passwords: List[str]) -> Dict:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return {"ip": ip, "port": port, "open": False, "redis": False, "auth_required": False, "version": "", "authed": False, "password_used": ""}
    try:
        is_redis, auth_required, version, authed, pw = await detect_redis(reader, writer, timeout, passwords)
        return {"ip": ip, "port": port, "open": True, "redis": is_redis, "auth_required": auth_required, "version": version, "authed": authed, "password_used": pw}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def scan_ips(ips: List[str], ports: List[int], timeout: float, concurrency: int, passwords: List[str]) -> List[Dict]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []
    tasks = []
    async def run_task(ip: str, port: int):
        async with sem:
            res = await scan_one(ip, port, timeout, passwords)
            results.append(res)
    for ip in ips:
        for p in ports:
            tasks.append(asyncio.create_task(run_task(ip, p)))
    if tasks:
        await asyncio.gather(*tasks)
    return results


def parse_ports(s: str) -> List[int]:
    if not s:
        return [6379]
    parts = [x.strip() for x in s.split(",") if x.strip()]
    ports = []
    for x in parts:
        if "-" in x:
            a, b = x.split("-", 1)
            a = int(a)
            b = int(b)
            if a > b:
                a, b = b, a
            ports.extend(list(range(a, b + 1)))
        else:
            ports.append(int(x))
    return sorted(set(ports))


def format_text(results: List[Dict]) -> str:
    lines = []
    for r in results:
        if r["redis"]:
            v = r["version"] if r["version"] else "未知"
            if r.get("authed"):
                lines.append(f"{r['ip']}:{r['port']} 可能为Redis 版本: {v} 状态: 已使用默认密码授权")
            else:
                auth = "需认证" if r["auth_required"] else "无需认证"
                lines.append(f"{r['ip']}:{r['port']} 可能为Redis 版本: {v} 状态: {auth}")
    if not lines:
        return "未发现可能的Redis服务"
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(prog="scan_redis", description="扫描IP或网段，识别可能存在的Redis服务并获取版本")
    parser.add_argument("target", help="IP、CIDR或范围，如 192.168.1.0/24 或 192.168.1.1-192.168.1.254")
    parser.add_argument("-p", "--ports", default="6379", help="端口，逗号或范围，如 6379,6380 或 6379-6382")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="连接与读写超时秒")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="并发限制")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text", help="输出格式")
    parser.add_argument("--no-default-auth", action="store_true", help="不尝试默认密码授权")
    parser.add_argument("-P", "--passwords", help="自定义密码列表，逗号分隔")
    parser.add_argument("-O", "--output-file", help="将扫描结果保存到指定文件")
    parser.add_argument("--append", action="store_true", help="以追加模式写入文件")
    args = parser.parse_args()
    ips = parse_targets(args.target)
    ports = parse_ports(args.ports)
    DEFAULT_PASSWORDS = ["", "redis", "password", "123456", "12345678", "admin", "root", "qwerty", "111111", "test", "guest"]
    pw_list: List[str] = []
    if not args.no_default_auth:
        pw_list.extend(DEFAULT_PASSWORDS)
    if args.passwords:
        pw_list.extend([p.strip() for p in args.passwords.split(",") if p.strip()])
    seen = set()
    passwords = []
    for p in pw_list:
        if p not in seen:
            passwords.append(p)
            seen.add(p)
    results = asyncio.run(scan_ips(ips, ports, args.timeout, args.concurrency, passwords))
    if args.output == "json":
        import json
        output_text = json.dumps([r for r in results if r["redis"]], ensure_ascii=False, indent=2)
    else:
        output_text = format_text(results)
    if args.output_file:
        mode = "a" if args.append else "w"
        with open(args.output_file, mode, encoding="utf-8") as f:
            f.write(output_text + "\n")
    print(output_text)


if __name__ == "__main__":
    main()

