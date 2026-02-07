# -*- coding: utf-8 -*-
"""
===================================
Web 服务器核心
===================================

职责：
1. 启动 HTTP 服务器
2. 处理请求分发
3. 提供后台运行接口
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Type
import base64
import binascii

from web.router import Router, get_router

logger = logging.getLogger(__name__)


# ============================================================
# HTTP 请求处理器
# ============================================================

class WebRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP 请求处理器
    
    将请求分发到路由器处理
    """

    # 类级别的路由器引用
    router: Router = None  # type: ignore
    username: str = ""
    password: str = ""

    def do_AUTHHEAD(self):
        """发送 401 响应及 WWW-Authenticate 头"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Restricted Area"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def authenticate(self):
        """检查 Authorization 头是否有效"""
        if not self.username:
            return True
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False

        if not auth_header.startswith('Basic '):
            return False

        try:
            # 解码 Base64 编码的凭证
            credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return False

        username, separator, password = credentials.partition(':')
        if separator != ':':
            return False

        return username == self.username and password == self.password

    def do_GET(self) -> None:
        """处理 GET 请求"""
        if not self.authenticate():
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')
            return
        self.router.dispatch(self, "GET")
    
    def do_POST(self) -> None:
        """处理 POST 请求"""
        if not self.authenticate():
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')
            return
        self.router.dispatch_post(self)

    def log_message(self, fmt: str, *args) -> None:
        """自定义日志格式（使用 logging 而非 stderr）"""
        # 可以取消注释以启用请求日志
        # logger.debug(f"[WebServer] {self.address_string()} - {fmt % args}")
        pass


# ============================================================
# Web 服务器
# ============================================================

class WebServer:
    """
    Web 服务器
    
    封装 ThreadingHTTPServer，提供便捷的启动和管理接口
    
    使用方式：
        # 前台运行
        server = WebServer(host="127.0.0.1", port=8000)
        server.run()
        
        # 后台运行
        server = WebServer(host="127.0.0.1", port=8000)
        server.start_background()
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        router: Optional[Router] = None,
        username: str = "",
        password: str = ""
    ):
        """
        初始化 Web 服务器
        
        Args:
            host: 监听地址
            port: 监听端口
            router: 路由器实例（可选，默认使用全局路由）
        """
        self.host = host
        self.port = port
        self.router = router or get_router()
        self.username = username
        self.password = password
        
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
    
    @property
    def address(self) -> str:
        """服务器地址"""
        return f"http://{self.host}:{self.port}"
    
    def _create_handler_class(self) -> Type[WebRequestHandler]:
        """创建带路由器引用的处理器类"""
        class Handler(WebRequestHandler):
            pass

        Handler.router = self.router
        Handler.username = self.username
        Handler.password = self.password
        return Handler
    
    def _create_server(self) -> ThreadingHTTPServer:
        """创建 HTTP 服务器实例"""
        handler_class = self._create_handler_class()
        return ThreadingHTTPServer((self.host, self.port), handler_class)
    
    def run(self) -> None:
        """
        前台运行服务器（阻塞）
        
        按 Ctrl+C 退出
        """
        self._server = self._create_server()
        
        logger.info(f"WebUI 服务启动: {self.address}")
        print(f"WebUI 服务启动: {self.address}")
        
        # 打印路由列表
        routes = self.router.list_routes()
        if routes:
            logger.info("已注册路由:")
            for method, path, desc in routes:
                logger.info(f"  {method:6} {path:20} - {desc}")
        
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            logger.info("收到退出信号，服务器关闭")
        finally:
            self._server.server_close()
            self._server = None
    
    def start_background(self) -> threading.Thread:
        """
        后台运行服务器（非阻塞）
        
        Returns:
            服务器线程
        """
        self._server = self._create_server()
        
        def serve():
            logger.info(f"WebUI 已启动: {self.address}")
            print(f"WebUI 已启动: {self.address}")
            try:
                self._server.serve_forever()
            except Exception as e:
                logger.error(f"WebUI 发生错误: {e}")
            finally:
                if self._server:
                    self._server.server_close()
        
        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self._thread
    
    def stop(self) -> None:
        """停止服务器"""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            logger.info("WebUI 服务已停止")
    
    def is_running(self) -> bool:
        """检查服务器是否运行中"""
        return self._server is not None


# ============================================================
# 便捷函数
# ============================================================

def run_server_in_thread(
    host: str = "127.0.0.1",
    port: int = 8000,
    router: Optional[Router] = None,
    username: str = "",
    password: str = ""
) -> threading.Thread:
    """
    在后台线程启动 WebUI 服务器
    
    Args:
        host: 监听地址
        port: 监听端口
        router: 路由器实例（可选）
        
    Returns:
        服务器线程
    """
    server = WebServer(host=host, port=port, router=router, username=username, password=password)
    return server.start_background()


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    router: Optional[Router] = None
) -> None:
    """
    前台运行 WebUI 服务器（阻塞）
    
    Args:
        host: 监听地址
        port: 监听端口
        router: 路由器实例（可选）
    """
    server = WebServer(host=host, port=port, router=router)
    server.run()
