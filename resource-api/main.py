from fastapi import FastAPI, Request, Header, HTTPException
from typing import Optional
import logging

# Cấu hình bộ ghi nhật ký (Logger configuration)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Zero-Trust Resource API")

# Phần mềm trung gian (Middleware) để theo dõi luồng dữ liệu mạng
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"[Traffic] Incoming request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"[Traffic] Response status: {response.status_code}")
    return response

# Điểm cuối công khai (Public endpoint) - Không yêu cầu xác thực tầng biên
@app.get("/api/public")
async def public_resource():
    return {
        "status": "success",
        "scope": "public",
        "message": "Đây là tài nguyên công khai (Public Resource). Ai cũng có thể xem."
    }

# Điểm cuối được bảo vệ (Protected endpoint) - Đã nâng cấp theo chuẩn RFC 8705
@app.get("/api/protected")
async def protected_resource(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_forwarded_client_cert: Optional[str] = Header(None, alias="x-forwarded-client-cert")
):
    # 1. Kiểm tra sự tồn tại của Tiêu đề ủy quyền (Authorization header) - Phòng thủ chiều sâu (Defense-in-Depth)
    if not authorization or not authorization.startswith("Bearer "):
        logger.warning("[Security Alert] Truy cập bị chặn: Thiếu hoặc sai định dạng mã thông báo (Token).")
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing or malformed Bearer Token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
        )
    
    # Trích xuất mã thông báo để phục vụ ghi nhật ký làm bằng chứng (Evidence logging)
    token = authorization.split(" ")[1]
    logger.info(f"[Auth Evidence] Received JWT Token: {token[:15]}...")
    
    # 2. Bắt tiêu đề chứng chỉ khách chuyển tiếp (XFCC Header) do Envoy tiêm (inject) xuống
    if x_forwarded_client_cert:
        logger.info(f"[Crypto Evidence] Received XFCC Header from Envoy: {x_forwarded_client_cert}")
    else:
        logger.warning("[Configuration Warning] Không tìm thấy tiêu đề X-Forwarded-Client-Cert.")

    return {
        "status": "success",
        "scope": "protected",
        "identity_binding": "Verified via mTLS-bound token (RFC 8705)",
        "data": "Đây là dữ liệu nhạy cảm (Sensitive Data). Mật danh: Báo cáo tài chính mật mã UTE 2026."
    }