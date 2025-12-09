import json
import os
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get('elkokkk', 'kscvevhbjvbeyrgeuvb')
# مفتاح سري للجلسات (يجب تغييره في الإنتاج)
#app.secret_key = 'Wp0Z&a!c9Qx$g2Jt7H^vY5mP#rL4sB8K'
# مفتاح سري لتوقيع HMAC (يجب أن يكون معقداً وسرياً للغاية ومخزناً خارج الكود)
HMAC_SECRET_KEY = 'Fr0ntK!tch3n_Ord3rS3cur3_&Zf9Lp@qYc7Dv6hX2GjM4wT3kR8B5nU'
ADMIN_USERNAME = "#AdMiN_m@KoK#"
PRODUCTS_FILE = 'products.json'
ORDERS_FILE = 'orders.json'

# =======================================================
# وظائف مساعدة أمنية وعامة
# =======================================================

def get_data(filename):
    """قراءة البيانات من ملف JSON."""
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
    """كتابة البيانات إلى ملف JSON."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def is_admin():
    """التحقق من صلاحيات الأدمن."""
    return session.get('logged_in') and session.get('role')=='Admin'

def is_logged_in():
    """التحقق من تسجيل الدخول."""
    return session.get('logged_in') and session.get('role') in ['Admin','User']

# --- وظائف HMAC (لتأمين طلبات المستخدمين) ---
def sign_data(data_to_sign, timestamp):
    """إنشاء توقيع HMAC للبيانات لمنع التزوير والـ Replay Attack."""
    # نجمع البيانات التي نريد توقيعها (Total, Mobile, Timestamp)
    data_string = f"{data_to_sign['total']}:{data_to_sign['mobile']}:{timestamp}"
    signature = hmac.new(
        HMAC_SECRET_KEY.encode('utf-8'),
        data_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

# --- وظائف CSRF (لتأمين الأدمن) ---
def generate_csrf_token():
    """توليد رمز CSRF وحفظه في الجلسة إذا لم يكن موجوداً."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def check_csrf_token(request_data):
    """التحقق من أن الرمز المرسل يطابق الرمز المخزن في الجلسة."""
    token_from_request = None
    if request_data.form:
        token_from_request = request_data.form.get('csrf_token')
    else: 
        try:
            json_data = request_data.get_json(silent=True)
            token_from_request = json_data.get('csrf_token') if json_data else None
        except:
             pass

    token_from_session = session.get('csrf_token')
    
    return token_from_request and token_from_session and token_from_request == token_from_session

# =======================================================
# مسارات الدخول والخروج
# =======================================================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form.get('username')
        if not username:
             return render_template('login.html', ADMIN_USERNAME=ADMIN_USERNAME, error="الرجاء إدخال اسم المستخدم"), 400
        
        if username == ADMIN_USERNAME:
            session['logged_in']=True
            session['role']='Admin'
            session['username']=username
            return redirect(url_for('admin_dashboard'))
        else:
            session['logged_in']=True
            session['role']='User'
            session['username']=username
            return redirect(url_for('menu'))
    return render_template('login.html', ADMIN_USERNAME=ADMIN_USERNAME, error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =======================================================
# لوحة الأدمن (مؤمنة بـ CSRF)
# =======================================================
@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        return redirect(url_for('login'))
    generate_csrf_token() 
    products = get_data(PRODUCTS_FILE)
    orders = get_data(ORDERS_FILE)
    return render_template('admin_dashboard.html', products=products, orders=orders)

@app.route('/admin/update_price', methods=['POST'])
def update_price():
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success':False,'message':'Forbidden - ليس لديك صلاحية أو خطأ أمني: رمز CSRF غير صالح.'}),403
        
    product_id=request.form.get('id')
    new_price=request.form.get('price')
    
    try:
        new_price=float(new_price)
        if new_price <= 0:
             return jsonify({'success':False,'message':'السعر يجب أن يكون قيمة موجبة'}),400
    except:
        return jsonify({'success':False,'message':'السعر يجب أن يكون رقماً صحيحاً أو عشرياً'}),400
        
    products=get_data(PRODUCTS_FILE)
    found=False
    for p in products:
        if p['id']==product_id:
            p['price']=new_price
            found=True
            break
            
    if found:
        save_data(PRODUCTS_FILE,products)
        return jsonify({'success':True,'message':'تم تحديث السعر بنجاح'})
    return jsonify({'success':False,'message':'المنتج غير موجود'}),404

@app.route('/admin/add_product', methods=['POST'])
def add_product():
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success':False,'message':'Forbidden - ليس لديك صلاحية أو خطأ أمني: رمز CSRF غير صالح.'}),403
        
    data=request.get_json()
    name = data.get('name')
    price = data.get('price')
    try:
        price = float(price)
        if price <= 0: raise ValueError
    except:
        return jsonify({'success':False,'message':'خطأ: السعر غير صالح.'}),400
        
    products=get_data(PRODUCTS_FILE)
    new_id=f"p{len(products)+1}"
    products.append({
        "id":new_id,
        "name":name,
        "price":price,
        "image":data.get('image','/static/img/default.svg'),
        "category":data.get('category','عام')
    })
    save_data(PRODUCTS_FILE,products)
    return jsonify({'success':True,'message':'تم إضافة المنتج'})

@app.route('/admin/delete_product', methods=['POST'])
def delete_product():
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success':False,'message':'Forbidden - ليس لديك صلاحية أو خطأ أمني: رمز CSRF غير صالح.'}),403
        
    data=request.get_json()
    product_id=data.get('id')
    products=get_data(PRODUCTS_FILE)
    products=[p for p in products if p['id']!=product_id]
    save_data(PRODUCTS_FILE,products)
    return jsonify({'success':True,'message':'تم حذف المنتج'})
# =======================================================
# لوحة الأدمن (مؤمنة بـ CSRF)
# =======================================================
# ... (المسارات السابقة) ...

@app.route('/admin/delete_all_orders', methods=['POST'])
def delete_all_orders():
    """مسح جميع الطلبات المخزنة في ملف ORDERS_FILE."""
    # 1. التحقق من صلاحية الأدمن ورمز CSRF
    if not is_admin() or not check_csrf_token(request):
        return jsonify({'success':False,'message':'Forbidden - ليس لديك صلاحية أو خطأ أمني: رمز CSRF غير صالح.'}),403
        
    try:
        # 2. مسح جميع البيانات عن طريق حفظ قائمة فارغة
        save_data(ORDERS_FILE, [])
        
        # 3. إعادة التوجيه إلى لوحة التحكم بعد نجاح العملية
        # يفضل استخدام نظام الـ flash messages لإظهار رسالة النجاح في صفحة admin_dashboard
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"Error deleting orders: {e}")
        # إذا كنت تستخدم flash: flash("خطأ في حذف الطلبات.")
        return redirect(url_for('admin_dashboard'))

# ... (باقي المسارات) ...

# =======================================================
# مسارات المستخدم (مؤمنة بـ HMAC)
# =======================================================
@app.route('/')
@app.route('/menu')
def menu():
    if not is_logged_in():
        return redirect(url_for('login'))
    products=get_data(PRODUCTS_FILE)
    categories=sorted(list({p.get('category','عام') for p in products}))
    return render_template('menu.html', products=products, categories=categories)

# مسار جديد: للحصول على توقيع HMAC
@app.route('/get_order_signature', methods=['POST'])
def get_order_signature():
    if not is_logged_in():
        return jsonify({'success':False,'message':'يجب تسجيل الدخول لإتمام الطلب'}),401
    
    data = request.get_json()
    total = data.get('total')
    mobile = data.get('mobile')
    
    if total is None or mobile is None:
        return jsonify({'success':False,'message':'بيانات التوقيع غير كاملة'}),400

    current_timestamp = int(time.time())
    
    data_to_sign = {'total': total, 'mobile': mobile}
    signature = sign_data(data_to_sign, current_timestamp)
    
    return jsonify({
        'success': True,
        'signature': signature,
        'timestamp': current_timestamp
    })


@app.route('/place_order', methods=['POST'])
def place_order():
    if not is_logged_in():
        return jsonify({'success':False,'message':'يجب تسجيل الدخول لإتمام الطلب'}),401
        
    data=request.get_json()
    mobile=data.get('mobile')
    location=data.get('location')
    total_from_client=data.get('total', 0.0)
    client_signature=data.get('signature')
    client_timestamp=data.get('timestamp')
    cart_items=data.get('cart', [])

    # 1. التحقق من صحة بيانات الإدخال (Validation)
    if not mobile or not mobile.isdigit() or len(mobile)!=11:
        return jsonify({'success':False,'message':'خطأ: رقم الهاتف غير صحيح (يجب أن يكون 11 رقم)'}),400
    if not location or len(location)<5:
         return jsonify({'success':False,'message':'خطأ: يجب إدخال موقع توصيل واضح'}),400
    if not cart_items:
         return jsonify({'success':False,'message':'خطأ: سلة الطلبات فارغة'}),400
         
    # 2. التحقق من صلاحية الوقت (Replay Attack Prevention)
    try:
        # يجب أن يكون التوقيت خلال 5 دقائق من الوقت الحالي
        order_time = datetime.fromtimestamp(client_timestamp)
        time_diff = datetime.now() - order_time
        if time_diff > timedelta(minutes=5) or time_diff < timedelta(seconds=-5): 
             return jsonify({'success':False,'message':'خطأ أمني: الطلب قديم جداً أو توقيت غير صالح (Replay Attack)'}),403
    except:
         return jsonify({'success':False,'message':'خطأ في توقيت الطلب'}),400
         
    # 3. التحقق من التوقيع (HMAC Validation - Anti-Tampering)
    data_to_sign_on_server = {'total': total_from_client, 'mobile': mobile}
    expected_signature = sign_data(data_to_sign_on_server, client_timestamp)

    if expected_signature != client_signature:
        return jsonify({'success':False,'message':'خطأ أمني: توقيع الطلب غير صحيح (بيانات الطلب تم التلاعب بها)'}),403
        
    # 4. التحقق من صحة السعر الإجمالي (Anti-Tampering - Server-Side Price Check)
    all_products = {p['id']: p for p in get_data(PRODUCTS_FILE)}
    calculated_total = 0.0
    
    for item in cart_items:
        product_id = item.get('id')
        qty = item.get('qty', 0)
        
        if product_id not in all_products or qty <= 0:
             return jsonify({'success':False,'message':f'خطأ: المنتج {product_id} غير متوفر أو الكمية غير صالحة'}),400
             
        actual_price = all_products[product_id]['price']
        
        # تحقق من أن السعر المرسل من العميل يطابق السعر الحقيقي في قاعدة البيانات
        if abs(item.get('price', 0) - actual_price) > 0.01:
             return jsonify({'success':False,'message':'خطأ أمني: تم التلاعب بسعر أحد العناصر.'}),403

        calculated_total += actual_price * qty
        
    # المقارنة النهائية: السعر الإجمالي
    if abs(calculated_total - total_from_client) > 0.01:
        return jsonify({'success':False,'message':'خطأ أمني: السعر الإجمالي غير صحيح. تم إيقاف الطلب.'}),403


    # 5. إذا نجحت كل الفحوصات الأمنية، يتم حفظ الطلب
    orders=get_data(ORDERS_FILE)
    order_id=f"ORD{len(orders)+1:04d}"
    orders.append({
        "order_id":order_id,
        "user":session.get('username'),
        "status":"جديد",
        "total":calculated_total, 
        "order_items":cart_items,
        "mobile":mobile,
        "location":location,
        "timestamp":time.strftime("%Y-%m-%d %H:%M:%S")
    })
    save_data(ORDERS_FILE,orders)
    return jsonify({'success':True,'message':f'🎉 تم استلام طلبك بنجاح رقم {order_id}. سيتم التواصل معك قريباً.'})


if __name__=='__main__':
    # تهيئة بيانات المنتجات إذا لم تكن موجودة
    get_data(PRODUCTS_FILE) 
    
    # أمر التشغيل (مع debug=True)
    print("Running Flask server on http://0.0.0.0:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
