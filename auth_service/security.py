from passlib.context import CryptContext

_pwd_ctx = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=19 * 1024,  # 19 MiB
    argon2__time_cost=2,
    argon2__parallelism=1,
)

def hash_secret(raw: str) -> str:
    return _pwd_ctx.hash(raw)

def verify_secret(raw: str, hashed: str) -> bool:
    return _pwd_ctx.verify(raw, hashed)
