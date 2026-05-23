#!/usr/bin/env python3
"""
Flux Server - 入口
Decentralized Minecraft Server - Hardware Validator

synergyedge Team

用法:
  python main.py              # 启动图形化控制台
  python main.py --cli        # 启动命令行模式
  python main.py --dashboard  # 仅启动监控面板
"""

import sys
import asyncio
import signal
import logging


def setup_logging():
    """配置日志"""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(name)s %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )


def run_gui():
    """启动图形化控制台"""
    try:
        from flux_dashboard import FluxDashboard
        app = FluxDashboard()
        app.run()
    except ImportError as e:
        print(f"Error: Cannot import GUI module: {e}")
        print("Make sure tkinter is installed: apt install python3-tk")
        sys.exit(1)


def run_cli():
    """启动命令行模式（无GUI）"""
    setup_logging()
    logger = logging.getLogger("flux")

    from server import FluxServer
    server = FluxServer()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler():
        logger.info("Received shutdown signal")
        loop.create_task(server.shutdown())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            signal.signal(sig, lambda s, f: signal_handler())

    try:
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")
        loop.run_until_complete(server.shutdown())
    finally:
        loop.close()
        logger.info("Flux server stopped")


def main():
    if "--cli" in sys.argv:
        run_cli()
    else:
        run_gui()


if __name__ == "__main__":
    main()
