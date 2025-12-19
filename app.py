import os
import re
import uvicorn
import smtplib
import random
from json import dumps as json_dumps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session


# 1. CẤU HÌNH EMAIL 

SENDER_EMAIL = os.getenv("SENDER_EMAIL", "thengudot1233@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "sabr awjk ssqo dblh")

def send_verification_email(receiver_email):
    verification_code = str(random.randint(100000, 999999))
    subject = "Mã xác thực EduManager"
    
    body = f"""
    <div style="font-family: Arial; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #4361ee;">Mã Xác Thực Bảo Mật</h2>
        <p>Mã OTP của bạn là: <b style="font-size: 24px; color: #ef233c; letter-spacing: 3px;">{verification_code}</b></p>
        <p>Mã này dùng để xác thực đăng ký hoặc đổi mật khẩu.</p>
    </div>
    """
    
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        return verification_code
    except Exception as e:
        print(f"Lỗi gửi email: {e}")
        return None


# 2. CẤU HÌNH DATABASE
SQLALCHEMY_DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    email = Column(String, unique=True) 
    phone = Column(String) 
    role = Column(String, default="teacher")
    full_name = Column(String)
    verification_code = Column(String, nullable=True)

class Classroom(Base):
    __tablename__ = "classrooms"
    id = Column(Integer, primary_key=True, index=True)
    room_name = Column(String, unique=True, index=True) 
    capacity = Column(Integer)                         
    equipment = Column(String)                        
    status = Column(String, default="Available")

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer)
    user_id = Column(Integer)
    booker_name = Column(String) 
    start_time = Column(String) 
    duration_hours = Column(String)
    status = Column(String, default="Confirmed")

Base.metadata.create_all(bind=engine)


# 3. KHỞI TẠO APP & DEPENDENCIES

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.filters['tojson'] = json_dumps

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- HELPER FUNCTIONS ---
def get_current_user(request: Request, db: Session = Depends(get_db)):
    username = request.cookies.get("current_user")
    if not username: return None
    return db.query(User).filter(User.username == username).first()

def require_admin(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Chỉ Admin mới có quyền này.")
    return user

def require_staff(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.role not in ["admin", "teacher"]:
        raise HTTPException(status_code=403, detail="Chỉ Giáo viên hoặc Admin mới có quyền này.")
    return user


# 4. CÁC API XỬ LÝ (LOGIC)


#ĐĂNG KÝ: GỬI MÃ OTP 
@app.post("/api/register/send-otp")
async def register_send_otp(data: dict, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data['username']).first():
        return {"status": "error", "message": "Tên đăng nhập đã tồn tại!"}
    if db.query(User).filter(User.email == data['email']).first():
        return {"status": "error", "message": "Email này đã được sử dụng!"}

    otp = send_verification_email(data['email'])
    if not otp: 
        return {"status": "error", "message": "Lỗi gửi mail. Hãy kiểm tra lại Email!"}
    
    # Trả về mã hash để client so sánh (hoặc lưu tạm vào DB nếu muốn bảo mật hơn)
    return {"status": "success", "message": "Đã gửi mã!", "server_otp": otp}

#  KÝ BƯỚC 2: XÁC NHẬN & TẠO USER 
@app.post("/api/register/confirm")
async def register_confirm(data: dict, db: Session = Depends(get_db)):
    # Tạo user mới 
    new_user = User(
        username=data['username'], 
        password=data['password'], 
        email=data['email'], 
        phone=data['phone'], 
        role=data['role'],
        full_name=data['full_name'],
        verification_code=None
    )
    db.add(new_user)
    db.commit()
    return {"status": "success", "message": "Đăng ký thành công!"}

# --- ĐĂNG NHẬP ---
@app.post("/api/login")
async def login(data: dict, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data['username'], User.password == data['password']).first()
    if user:
        response.set_cookie(key="current_user", value=user.username)
        return {"status": "success"}
    return {"status": "error", "message": "Sai tài khoản hoặc mật khẩu"}

# --- QUÊN MẬT KHẨU: GỬI OTP ---
@app.post("/api/forgot/send-otp")
async def forgot_send_otp(data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data['username']).first()
    if not user: return {"status": "error", "message": "User không tồn tại"}
    
    otp = send_verification_email(user.email)
    if not otp: return {"status": "error", "message": "Lỗi gửi mail"}
    
    user.verification_code = otp
    db.commit()
    hidden_email = user.email[:3] + "****" + user.email.split('@')[1]
    return {"status": "success", "message": f"Đã gửi mã tới {hidden_email}"}

# --- QUÊN MẬT KHẨU: ĐỔI PASS ---
@app.post("/api/forgot/reset")
async def forgot_reset(data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data['username']).first()
    if not user: return {"status": "error", "message": "User không tồn tại"}
    
    if user.verification_code != data['otp']:
        return {"status": "error", "message": "Sai mã OTP!"}
    
    user.password = data['new_password']
    user.verification_code = None
    db.commit()
    return {"status": "success", "message": "Đổi mật khẩu thành công!"}

# --- PROFILE: GỬI OTP ---
@app.post("/api/profile/send-otp")
async def profile_send_otp(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user: return {"status": "error", "message": "Chưa đăng nhập!"}
    
    otp = send_verification_email(user.email)
    if not otp: return {"status": "error", "message": "Không thể gửi email."}
    
    user.verification_code = otp
    db.commit()
    return {"status": "success", "message": "Đã gửi mã xác thực."}

# --- PROFILE: CẬP NHẬT THÔNG TIN ---
@app.post("/api/profile/update")
async def update_profile(data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user: return {"status": "error", "message": "Chưa đăng nhập!"}
    
    new_email = data.get('email')
    new_phone = data.get('phone')
    is_sensitive = (new_email and new_email != current_user.email) or (new_phone and new_phone != current_user.phone)
    
    if is_sensitive:
        otp_input = data.get('otp')
        if not otp_input: return {"status": "require_otp", "message": "Cần xác thực OTP"}
        if current_user.verification_code != otp_input:
            return {"status": "error", "message": "Mã OTP không đúng!"}
        current_user.verification_code = None

    if new_email: current_user.email = new_email
    if new_phone: current_user.phone = new_phone
    
    db.commit()
    return {"status": "success", "message": "Cập nhật thành công!"}

# --- API QUẢN LÝ PHÒNG & ĐẶT LỊCH (GIỮ NGUYÊN) ---
@app.post("/api/bookings/create")
async def create_booking(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_staff)):
    room = db.query(Classroom).filter(Classroom.id == data['room_id']).first()
    if not room or room.status == 'Maintenance': return {"status": "error", "message": "Phòng không khả dụng!"}
    
    booker_display = current_user.full_name if current_user.full_name else current_user.username
    db.add(Booking(room_id=data['room_id'], user_id=current_user.id, booker_name=booker_display, start_time=data['start_time'], duration_hours=data['duration_display']))
    db.commit()
    return {"status": "success"}

@app.post("/api/bookings/delete")
async def delete_booking(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_staff)):
    bk = db.query(Booking).filter(Booking.id == data['booking_id']).first()
    if not bk: return {"status": "error", "message": "Lỗi"}
    if current_user.role != 'admin' and bk.user_id != current_user.id: return {"status": "error", "message": "Không có quyền"}
    db.delete(bk)
    db.commit()
    return {"status": "success"}

@app.post("/api/rooms/create")
async def create_room(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    # SỬA LẠI: Lấy status từ dữ liệu gửi lên (data.get), nếu không có mới để mặc định Available
    status_input = data.get('status', 'Available') 
    
    db.add(Classroom(
        room_name=data['room_name'], 
        capacity=data['capacity'], 
        equipment=data['equipment'], 
        status=status_input 
    ))
    db.commit()
    return {"status": "success"}

@app.post("/api/rooms/update")
async def update_room(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    r = db.query(Classroom).filter(Classroom.id == data['room_id']).first()
    if r:
        r.room_name = data.get('room_name'); r.capacity = data.get('capacity'); r.equipment = data.get('equipment'); r.status = data.get('status')
        db.commit()
        return {"status": "success"}
    return {"status": "error"}

@app.post("/api/rooms/delete")
async def delete_room(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    r = db.query(Classroom).filter(Classroom.id == data['room_id']).first()
    if r: db.delete(r); db.commit(); return {"status": "success"}
    return {"status": "error"}

@app.post("/api/users/update")
async def update_user(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    u = db.query(User).filter(User.id == data['user_id']).first()
    if u:
        u.email = data.get('email'); u.phone = data.get('phone'); u.role = data.get('role')
        if data.get('new_password'): u.password = data['new_password']
        db.commit()
        return {"status": "success"}
    return {"status": "error"}

@app.post("/api/users/delete")
async def delete_user(data: dict, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    u = db.query(User).filter(User.id == data['user_id']).first()
    if u and u.id != current_user.id: db.delete(u); db.commit(); return {"status": "success"}
    return {"status": "error"}


# 5. CÁC ROUTE HTML (VIEWS)

@app.get("/", response_class=HTMLResponse)
async def root(request: Request): return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def reg(request: Request): return templates.TemplateResponse("register.html", {"request": request})

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot(request: Request): return templates.TemplateResponse("forgotpw.html", {"request": request})

@app.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request): return templates.TemplateResponse("verify.html", {"request": request})

@app.get("/logout")
async def logout(response: Response): response = RedirectResponse("/"); response.delete_cookie("current_user"); return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    u = get_current_user(request, db)
    if not u: return RedirectResponse("/")
    rooms = db.query(Classroom).all()
    booking_count = db.query(Booking).count() if u.role == 'admin' else db.query(Booking).filter(Booking.user_id == u.id).count()
    
    #  lịch sử 10 đơn gần nhất
    bookings_db = db.query(Booking).order_by(Booking.id.desc()).limit(10).all()
    history = []
    for b in bookings_db:
        r = db.query(Classroom).filter(Classroom.id == b.room_id).first()
        history.append({"booker": b.booker_name, "room_name": r.room_name if r else "Unknown", "time": b.start_time, "duration": b.duration_hours, "status": b.status})

    return templates.TemplateResponse("index.html", {
        "request": request, "username": u.username, "full_name": u.full_name, "role": u.role,
        "classrooms": rooms, "total_rooms": len(rooms), "active_rooms": len([r for r in rooms if r.status=='Available']),
        "booking_count": booking_count, "history": history
    })

@app.get("/room-management", response_class=HTMLResponse)
async def room_mgmt(request: Request, db: Session = Depends(get_db)):
    u = get_current_user(request, db)
    if not u: return RedirectResponse("/")
    return templates.TemplateResponse("room_management.html", {"request": request, "classrooms": db.query(Classroom).all(), "role": u.role, "username": u.username, "full_name": u.full_name})

@app.get("/booking-scheduler", response_class=HTMLResponse)
async def scheduler(request: Request, db: Session = Depends(get_db)):
    u = get_current_user(request, db)
    if not u: return RedirectResponse("/")
    bookings = [{"id":b.id, "room_id":b.room_id, "booker_name":b.booker_name, "start_time":b.start_time, "duration_hours":b.duration_hours} for b in db.query(Booking).all()]
    rooms = [{"id":c.id, "room_name":c.room_name, "capacity":c.capacity, "equipment":c.equipment, "status":c.status} for c in db.query(Classroom).all()]
    return templates.TemplateResponse("booking_scheduler.html", {"request": request, "classrooms": rooms, "bookings": bookings, "username": u.username, "role": u.role, "full_name": u.full_name})

@app.get("/user-management", response_class=HTMLResponse)
async def user_mgmt(request: Request, db: Session = Depends(get_db)):
    u = get_current_user(request, db)
    if not u or u.role != "admin": return RedirectResponse("/dashboard")
    return templates.TemplateResponse("user_management.html", {"request": request, "users": db.query(User).all(), "username": u.username, "role": u.role, "full_name": u.full_name})

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, db: Session = Depends(get_db)):
    u = get_current_user(request, db)
    if not u: return RedirectResponse("/")
    user_bookings = db.query(Booking).filter(Booking.user_id == u.id).all()
    history = [{"room_name": (db.query(Classroom).filter(Classroom.id==b.room_id).first().room_name if db.query(Classroom).filter(Classroom.id==b.room_id).first() else "Unknown"), "start_time": b.start_time, "duration": b.duration_hours, "status": b.status} for b in user_bookings]
    return templates.TemplateResponse("profile.html", {"request": request, "user": u, "username": u.username, "role": u.role, "full_name": u.full_name, "history": history})

# --- SỰ KIỆN KHỞI ĐỘNG (TẠO DỮ LIỆU MẪU) ---
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    # Tạo Admin mặc định nếu chưa có
    if not db.query(User).filter(User.username == "admin").first():
        db.add(User(username="admin", password="123", role="admin", full_name="Quản Trị Viên", email="admin@edu.vn", phone="0999999999"))
    
    # Tạo Phòng học mẫu nếu chưa có
    if not db.query(Classroom).first():
        rooms = [
            Classroom(room_name="Phòng A101", capacity=40, equipment="Máy chiếu", status="Available"),
            Classroom(room_name="Phòng A102", capacity=40, equipment="TV", status="Available"),
            Classroom(room_name="Hội trường", capacity=100, equipment="Full", status="Available")
        ]
        db.add_all(rooms)
    db.commit()
    db.close()

#ip đổi mật khẩu
# --- Thêm đoạn này vào app.py để sửa lỗi 404 ---

@app.post("/api/profile/change-password")
async def profile_change_pass(data: dict, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user: return {"status": "error", "message": "Chưa đăng nhập!"}

    # Kiểm tra mã OTP
    if user.verification_code != data['otp']:
        return {"status": "error", "message": "Mã xác thực không đúng!"}
    
    # Đổi mật khẩu
    user.password = data['new_password']
    user.verification_code = None # Xóa mã sau khi dùng xong
    db.commit()
    
    return {"status": "success", "message": "Cập nhật mật khẩu thành công!"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)