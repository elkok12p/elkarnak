=import json
import os
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
# 🟢 استيراد وظيفة التعقيم لـ XSS
from markupsafe import escape 

app = Flask(__name__)
# 🔒 مفتاح سري قوي جداً للجلسات (يجب تغييره في بيئة الإنتاج)
app.secret_key = 'Wp0Z&a!c9Qx$g2Jt7H^vY5mP#rL4sB8K'
# 🔒 مفتاح سري للتوقيع (HMAC)
HMAC_SECRET_KEY = 'Fr0ntK!tch3n_Ord3rS3cur3_&Zf9Lp@qYc7Dv6hX2GjM4wT3kR8B5nU'
ADMIN_USERNAME = "#AdMiN_m@KoK#"
PRODUCTS_FILE = 'products.json'
ORDERS_FILE = 'orders.json'
TMP_SUFFIX = '.tmp'


# =======================================================
# متغيّرات تحديد المعدل (Rate Limiting)
# =======================================================
# تخزين آخر وقت طلب لكل IP. 
# في بيئات الإنتاج، يفضل استخدام Redis أو DB.
IP_LAST_ORDER_TIME = {} 
ORDER_RATE_LIMIT_SECONDS = 60 # مدة الانتظار الأدنى (1 دقيقة)


# 🔐 جلسة الأدمن النشطة (واحدة فقط)
# هذا المتغير يحمل الجلسة النشطة الوحيدة للأدمن على مستوى السيرفر.
ACTIVE_ADMIN_SESSION = {
    "session_id": None,
    "device_fingerprint": None
}


# =======================================================
# وظائف مساعدة أمنية وعامة
# =======================================================

def get_data(filename):
    """قراءة البيانات من ملف JSON. يضمن القراءة من القرص في كل مرة."""
    if not os.path.exists(filename):
        if filename == PRODUCTS_FILE:
            return [
                {"id": "p1", "name": "برجر لحم كلاسيك", "price": 85.0, "image": "/static/img/burger.svg", "category":"برجر"},
                {"id": "p2", "name": "بيتزا مارجريتا حجم وسط", "price": 120.0, "image": "/static/img/pizza.svg", "category":"بيتزا"}
            ]
        return []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return []

def save_data(filename, data):
    """✅ كتابة البيانات إلى ملف JSON بشكل آمن (Atomicity) باستخدام ملف مؤقت."""
    tmp_file = filename + TMP_SUFFIX
    try:
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, filename)
    except Exception as e:
        print(f"Error saving {filename}: {e}")
        try:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
        except:
            pass
            
# 🆕 دالة توليد بصمة الجهاز
def get_device_fingerprint():
    """توليد بصمة فريدة للجهاز بناءً على IP و User-Agent."""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    raw = f"{ip}|{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()

def is_admin():
    """
    التحقق من صلاحيات الأدمن ومطابقة الجلسة النشطة.
    التحقق الأمني الجديد: يجب أن يتطابق 'admin_session_id' في الجلسة مع 'session_id' النشط في ACTIVE_ADMIN_SESSION.
    """
    if not session.get('logged_in') or session.get('role') != 'Admin':
        return False

    return (
        session.get('admin_session_id') ==
        ACTIVE_ADMIN_SESSION.get("session_id")
    )

def is_logged_in():
    """التحقق من تسجيل الدخول."""
    return session.get('logged_in') and session.get('role') in ['Admin','User']

# 🟢 وظيفة جديدة لتحديد معدل الطلبات حسب IP
def check_rate_limit(ip_address):
    """
    التحقق من أنه لم يتم تقديم طلب من هذا IP خلال فترة ORDER_RATE_LIMIT_SECONDS.
    إذا تجاوز المستخدم معدل الطلبات، يتم إرجاع False والوقت المتبقي.
    """
    now = time.time()
    
    # 1. تحقق من وجود IP في سجل الطلبات
    if ip_address in IP_LAST_ORDER_TIME:
        last_order_time = IP_LAST_ORDER_TIME[ip_address]
        time_since_last_order = now - last_order_time
        
        # 2. إذا لم ينقض الوقت المطلوب
        if time_since_last_order < ORDER_RATE_LIMIT_SECONDS:
            time_remaining = int(ORDER_RATE_LIMIT_SECONDS - time_since_last_order)
            return False, time_remaining

    # 3. تحديث الوقت الحالي لـ IP، للسماح بالطلب
    IP_LAST_ORDER_TIME[ip_address] = now
    
    return True, 0

# --- وظائف HMAC (لتأمين طلبات المستخدمين) ---
def sign_data(data_to_sign, timestamp):
    """✅ إنشاء توقيع HMAC للبيانات لمنع التزوير والـ Replay Attack."""
    data_string = f"{data_to_sign['total']}:{data_to_sign['mobile']}:{timestamp}"
    signature = hmac.new(
        HMAC_SECRET_KEY.encode('utf-8'),
        data_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

# --- وظائف CSRF (لتأمين الأدمن) ---
def generate_csrf_token():
    """✅ توليد رمز CSRF وحفظه في الجلسة."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def check_csrf_token(req):
    """✅ التحقق من رمز CSRF من مختلف المصادر (Header, Form, JSON Body)."""
    token_from_request = None
    token_from_request = req.headers.get('X-CSRFToken') or req.headers.get('X-CSRF-Token')
    
    if not token_from_request and req.form:
        token_from_request = req.form.get('csrf_token')
    
    if not token_from_request:
        try:
            json_data = req.get_json(silent=True)
            if json_data:
                token_from_request = json_data.get('csrf_token')
        except:
            pass

    token_from_session = session.get('csrf_token')
    return bool(token_from_request and token_from_session and token_from_request == token_from_session)

# =======================================================
# مسارات الدخول والخروج
# =======================================================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            return render_template('login.html', ADMIN_USERNAME=ADMIN_USERNAME, error="الرجاء إدخال اسم المستخدم"), 400

        # ✅ التعقيم (Sanitization) يتم تطبيقه قبل التخزين في الجلسة لمنع Stored XSS
        safe_username = str(escape(username))

        # 🛑 منطق قفل جلسة الأدمن هنا 🛑
        if username == ADMIN_USERNAME:
            device_fp = get_device_fingerprint()

            # ❌ في جلسة أدمن شغالة على جهاز آخر
            if ACTIVE_ADMIN_SESSION["session_id"] and ACTIVE_ADMIN_SESSION["device_fingerprint"] != device_fp:
                return render_template(
                    'login.html',
                    ADMIN_USERNAME=ADMIN_USERNAME,
                    error="forbidden 403❌"
                ), 403

            # ✅ تسجيل الدخول وتحديث قفل الجلسة النشطة
            admin_session_id = secrets.token_hex(16)

            session['logged_in'] = True
            session['role'] = 'Admin'
            session['username'] = safe_username
            session['admin_session_id'] = admin_session_id # حفظ الـ ID الفريد في الجلسة

            ACTIVE_ADMIN_SESSION["session_id"] = admin_session_id
            ACTIVE_ADMIN_SESSION["device_fingerprint"] = device_fp

            generate_csrf_token() # توليد توكن CSRF للأدمن
            return redirect(url_for('admin_dashboard'))
        # ------------------------------------
        
        else:
            session['logged_in'] = True
            session['role'] = 'User'
            session['username'] = safe_username
            return redirect(url_for('menu'))
    return render_template('login.html', ADMIN_USERNAME=ADMIN_USERNAME, error=None)

@app.route('/logout')
def logout():
    """✅ مسار الخروج: يمسح الجلسة بالكامل ويحرر قفل الأدمن إذا كان هو المسجّل."""
    if session.get('role') == 'Admin':
        # تحرير القفل للسماح لجهاز آخر بتسجيل الدخول
        ACTIVE_ADMIN_SESSION["session_id"] = None
        ACTIVE_ADMIN_SESSION["device_fingerprint"] = None

    session.clear()
    return redirect(url_for('login'))


# =======================================================
# لوحة الأدمن - مسارات CRUD (مؤمنة بـ CSRF)
# جميع هذه المسارات محمية الآن بواسطة is_admin() المُعدّلة.
# =======================================================
@app.route('/admin/dashboard')
def admin_dashboard():
    # is_admin() تتحقق الآن من قفل الجلسة
    if not is_admin():
        return redirect(url_for('login'))
    generate_csrf_token()
    products = get_data(PRODUCTS_FILE)
    orders = get_data(ORDERS_FILE)
    return render_template('admin_dashboard.html', products=products, orders=orders)

@app.route('/admin/get_orders')
def get_orders():
    """يرجع كل الطلبات (يُستخدم للـ Polling في Dashboard)."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    orders = get_data(ORDERS_FILE)
    return jsonify({'success': True, 'orders': orders})

@app.route('/admin/update_price', methods=['POST'])
def update_price():
    """✅ مسار مؤمن بـ CSRF لتحديث السعر."""
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success': False, 'message': 'Forbidden - رمز CSRF غير صالح.'}), 403

    product_id = request.form.get('id')
    new_price = request.form.get('price')

    try:
        new_price = float(new_price)
        if new_price <= 0:
            return jsonify({'success': False, 'message': 'السعر يجب أن يكون قيمة موجبة'}), 400
    except:
        return jsonify({'success': False, 'message': 'السعر يجب أن يكون رقماً صحيحاً أو عشرياً'}), 400

    products = get_data(PRODUCTS_FILE)
    found = False
    for p in products:
        if p['id'] == product_id:
            p['price'] = new_price
            found = True
            break

    if found:
        save_data(PRODUCTS_FILE, products)
        return jsonify({'success': True, 'message': 'تم تحديث السعر بنجاح'})
    return jsonify({'success': False, 'message': 'المنتج غير موجود'}), 404

@app.route('/admin/add_product', methods=['POST'])
def add_product():
    """✅ مسار مؤمن بـ CSRF لإضافة منتج جديد مع تعقيم المدخلات."""
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success': False, 'message': 'Forbidden - رمز CSRF غير صالح.'}), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'بيانات غير صالحة'}), 400

    # ✅ تعقيم جميع البيانات النصية قبل الحفظ
    name = str(escape(data.get('name'))).strip()
    image = str(escape(data.get('image', '/static/img/default.svg'))).strip()
    category = str(escape(data.get('category', 'عام'))).strip()
    
    price = data.get('price')
    try:
        price = float(price)
        if price <= 0:
            raise ValueError
    except:
        return jsonify({'success': False, 'message': 'خطأ: السعر غير صالح.'}), 400

    products = get_data(PRODUCTS_FILE)
    # إضافة رمز عشوائي للـ ID لمنع التنبؤ
    new_id = f"p{len(products) + 1}-{secrets.token_hex(2)}" 
    products.append({
        "id": new_id,
        "name": name,
        "price": price,
        "image": image,
        "category": category
    })
    save_data(PRODUCTS_FILE, products)
    return jsonify({'success': True, 'message': 'تم إضافة المنتج'})

@app.route('/admin/delete_product', methods=['POST'])
def delete_product():
    """✅ مسار مؤمن بـ CSRF لحذف منتج."""
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success': False, 'message': 'Forbidden - رمز CSRF غير صالح.'}), 403

    data = request.get_json(silent=True)
    product_id = data.get('id') if data else None
    products = get_data(PRODUCTS_FILE)
    products = [p for p in products if p['id'] != product_id]
    save_data(PRODUCTS_FILE, products)
    return jsonify({'success': True, 'message': 'تم حذف المنتج'})

@app.route('/admin/delete_all_orders', methods=['POST'])
def delete_all_orders():
    """✅ مسار مؤمن بـ CSRF لمسح جميع الطلبات (إجراء خطير)."""
    if not is_admin() or not check_csrf_token(request):
        return "Forbidden - رمز CSRF غير صالح أو ليست لديك صلاحية.", 403

    save_data(ORDERS_FILE, [])
    return redirect(url_for('admin_dashboard'))

# =======================================================
# مسارات المستخدم (Menu & Ordering)
# =======================================================
@app.route('/')
@app.route('/menu')
def menu():
    products = get_data(PRODUCTS_FILE)
    categories = sorted(list(set(p['category'] for p in products)))
    is_user_logged_in = is_logged_in()
    return render_template('menu.html', products=products, categories=categories, is_logged_in=is_user_logged_in)

@app.route('/get_order_signature', methods=['POST'])
def get_order_signature():
    """نقطة نهاية لتوفير التوقيع الآمن (HMAC) للعميل قبل إرسال الطلب."""
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'الرجاء تسجيل الدخول أولاً'}), 401
    
    data = request.get_json(silent=True)
    if not data or 'total' not in data or 'mobile' not in data:
        return jsonify({'success': False, 'message': 'بيانات غير صالحة'}), 400

    try:
        timestamp = int(time.time())
        # إنشاء التوقيع بالبيانات الحساسة (الإجمالي ورقم الهاتف)
        signature = sign_data({'total': data['total'], 'mobile': data['mobile']}, timestamp)
        
        return jsonify({
            'success': True,
            'signature': signature,
            'timestamp': timestamp
        })
    except Exception as e:
        print(f"Error signing data: {e}")
        return jsonify({'success': False, 'message': 'خطأ داخلي في توليد التوقيع'}), 500


@app.route('/place_order', methods=['POST'])
def place_order():
    """✅ نقطة نهاية الطلب مؤمنة بـ HMAC و Anti-Tampering و Sanitization."""
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'الرجاء تسجيل الدخول أولاً'}), 401
    
    # ----------------------------------------------------
    # 🛑 1. التحقق من تحديد المعدل (Rate Limiting)
    # ----------------------------------------------------
    # نحصل على عنوان IP للعميل. يستخدم .get('X-Forwarded-For') إذا كنت تستخدم Proxy/Load Balancer
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    can_order, time_left = check_rate_limit(ip_address)
    if not can_order:
        # يتم الرد بخطأ 429 Too Many Requests
        return jsonify({
            'success': False, 
            'message': f'تم تجاوز معدل الطلبات. يرجى المحاولة بعد {time_left} ثانية.'
        }), 429 
    
    # ----------------------------------------------------
    # 🛑 2. متابعة عملية الطلب بعد التحقق من المعدل
    # ----------------------------------------------------
    data = request.get_json(silent=True)
    required_fields = ['total', 'cart', 'mobile', 'location', 'signature', 'timestamp']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'بيانات الطلب غير مكتملة'}), 400

    mobile = str(data['mobile']).strip()
    location = str(data['location']).strip()
    total_from_client = data.get('total', 0.0)
    client_signature = data.get('signature')
    client_timestamp = data.get('timestamp')
    cart_items = data.get('cart', [])

    # --- 3. التحقق من التوقيع (HMAC) والـ Replay Attack ---
    try:
        # 3.1 التحقق من التوقيع: هل تم التلاعب بالإجمالي أو الهاتف؟
        expected_signature = sign_data({'total': total_from_client, 'mobile': mobile}, client_timestamp)
        if expected_signature != client_signature:
            return jsonify({'success': False, 'message': 'فشل التحقق الأمني (التوقيع غير مطابق).'}), 403

        # 3.2 التحقق من صلاحية الوقت: هل الطلب جديد (خلال 60 ثانية)؟
        current_time = int(time.time())
        timestamp_diff = abs(current_time - int(client_timestamp))
        if timestamp_diff > 60: 
            return jsonify({'success': False, 'message': 'فشل التحقق الأمني (انتهت صلاحية الطلب).'}), 403

    except Exception as e:
        print(f"HMAC validation error: {e}")
        return jsonify({'success': False, 'message': 'خطأ أثناء التحقق الأمني'}), 500

    # --- 4. التحقق من صحة البيانات (Validation & Sanitization) ---
    if not mobile.isdigit() or len(mobile) != 11:
        return jsonify({'success': False, 'message': 'رقم الهاتف غير صحيح.'}), 400

    # ✅ تعقيم حقل الموقع قبل حفظه (لمنع XSS المخزن)
    location_safe = str(escape(location))

    # --- 5. التحقق من صحة السعر الإجمالي (Anti-Tampering - إعادة حساب الإجمالي) ---
    all_products = {p['id']: p for p in get_data(PRODUCTS_FILE)}
    calculated_total = 0.0
    
    safe_cart = []
    for item in cart_items:
        product_id = item.get('id')
        qty = item.get('qty', 0)
        
        if product_id not in all_products or qty <= 0:
            return jsonify({'success': False, 'message': f'خطأ: المنتج {product_id} غير متوفر أو الكمية غير صالحة'}), 400
            
        actual_price = all_products[product_id]['price']
        
        # ✅ التحقق الأمني: السعر المرسل للعنصر يجب أن يطابق السعر الحقيقي في قاعدة البيانات
        if abs(item.get('price', 0.0) - actual_price) > 0.01:
            return jsonify({'success': False, 'message': 'خطأ أمني: تم التلاعب بسعر أحد العناصر.'}), 403

        calculated_total += actual_price * qty
        
        # ✅ تعقيم وحفظ العنصر للسلة
        safe_cart.append({
            'id': str(escape(product_id)),
            'name': str(escape(item.get('name', ''))),
            'qty': qty,
            'price': actual_price # استخدام السعر المُحقق من الخادم
        })
            
    # ✅ المقارنة النهائية: هل الإجمالي المحسوب في الخادم يطابق الإجمالي المرسل والموقع؟
    if abs(calculated_total - total_from_client) > 0.01:
        return jsonify({'success': False, 'message': 'خطأ أمني: السعر الإجمالي غير صحيح. تم إيقاف الطلب.'}), 403

    # --- 6. حفظ الطلب ---
    orders = get_data(ORDERS_FILE)
    order_id = len(orders) + 1
    
    # ✅ التأكد من تعقيم اسم المستخدم من الجلسة قبل الحفظ
    username_safe = str(escape(session.get('username', 'ضيف')))

    new_order = {
        'order_id': f'#{order_id}',
        'user': username_safe,
        'mobile': mobile,
        'location': location_safe,
        'total': calculated_total, # استخدام الإجمالي المُحقق من الخادم
        'order_items': safe_cart, 
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    orders.append(new_order)
    save_data(ORDERS_FILE, orders)
    
    return jsonify({'success': True, 'message': f'تم استلام طلبك بنجاح. رقم الطلب: #{order_id}'})


if __name__ == '__main__':
    # تهيئة ملف المنتجات
    get_data(PRODUCTS_FILE)
    
    print("Running Flask server on http://0.0.0.0:5000")
    # تم إرجاع debug=False لبيئة الإنتاج الأمنية
    app.run(debug=False, host='0.0.0.0', port=5000)
