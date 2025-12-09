/* -----------------------------
    Cart Logic + Filtering + Modal + Secure HMAC Order
------------------------------*/

let cart = []; // مصفوفة السلة الرئيسية

/* 1) فتح/إغلاق لوحة السلة */
const toggleCartBtn = document.getElementById("toggleCart");
const cartPanel = document.getElementById("cartPanel");

toggleCartBtn?.addEventListener('click', () => {
    cartPanel.style.display = (cartPanel.style.display === "block") ? "none" : "block";
});

/* 2) إعادة حساب وعرض السلة */
function recalc() {
    const cartItems = document.getElementById('cartItems');
    const totalEl = document.getElementById('cartTotal');
    const cartCount = document.getElementById('cartCount');
    let total = 0;

    if (!cartItems || !totalEl || !cartCount) return;

    if (cart.length === 0) {
        cartItems.innerHTML = '<p style="text-align:center;opacity:0.7;">السلة فارغة</p>';
    } else {
        cartItems.innerHTML = '';
        cart.forEach(it => {
            const div = document.createElement('div');
            div.className = 'cart-item';
            div.innerHTML = `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;">
                    <div>${it.name} × ${it.qty}</div>
                    <div style="display:flex;align-items:center;gap:10px;">
                        <span>${(it.price * it.qty).toFixed(2)} ج.م</span>
                        <button class="remove-btn" data-id="${it.id}" style="background:transparent;color:#ff4f4f;padding:0;font-size:1.5rem;line-height:1;opacity:0.8;cursor:pointer;">&times;</button>
                    </div>
                </div>`;
            cartItems.appendChild(div);
            total += it.price * it.qty;
        });
    }

    totalEl.textContent = total.toFixed(2) + ' ج.م';
    cartCount.textContent = cart.length;

    if (cartPanel && cart.length > 0) {
        cartPanel.animate([{transform:'scale(1)'},{transform:'scale(1.01)'},{transform:'scale(1)'}], {duration:260});
    }
}
recalc();

/* 3) النقر العام (إضافة، حذف، فلترة) */
document.addEventListener('click', e => {
    // إضافة للسلة
    if (e.target.classList.contains('add-btn')) {
        const id = e.target.dataset.id;
        const name = e.target.dataset.name;
        const price = parseFloat(e.target.dataset.price);

        const qtyInput = e.target.closest('.product-card')?.querySelector('.qty');
        const qty = parseInt(qtyInput?.value || '1', 10);

        if (qty <= 0) return alert('اختر كمية صحيحة');

        const exist = cart.find(c => c.id === id);
        if (exist) {
            exist.qty += qty;
            e.target.animate([{transform:'translateX(0)'},{transform:'translateX(6px)'},{transform:'translateX(0)'}], {duration:260});
        } else {
            cart.push({id, name, price, qty});

            // أنيميشن الطيران
            const img = e.target.closest('.product-card')?.querySelector('img');
            if (img) {
                const fly = img.cloneNode(true);
                fly.style.position = 'fixed';
                fly.style.zIndex = 9999;
                fly.style.width = '80px';
                fly.style.height = '80px';
                const rect = img.getBoundingClientRect();
                fly.style.left = rect.left + 'px';
                fly.style.top = rect.top + 'px';
                document.body.appendChild(fly);

                const tr = toggleCartBtn?.getBoundingClientRect();
                if (tr) {
                    fly.animate(
                        [
                            {left: rect.left+'px', top: rect.top+'px', opacity:1},
                            {left: (tr.left+10)+'px', top: (tr.top+10)+'px', opacity:0.2, transform:'scale(0.3)'}
                        ],
                        {duration:700, easing:'cubic-bezier(.2,.9,.3,1)'}
                    ).onfinish = () => fly.remove();
                }
            }
        }
        recalc();
    }

    // حذف منتج
    if (e.target.classList.contains('remove-btn')) {
        const id = e.target.dataset.id;
        const index = cart.findIndex(item => item.id === id);
        if (index !== -1) {
            cart.splice(index, 1);
            recalc();
        }
    }

    // فلترة
    if (e.target.classList.contains('chip')) {
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        e.target.classList.add('active');

        const cat = e.target.dataset.cat;
        document.querySelectorAll('.product-card').forEach(card => {
            card.style.display = (cat === 'all' || card.dataset.cat === cat) ? 'block' : 'none';
        });
    }
});

/* 4) مودال الطلب */
const modal = document.getElementById('orderModal');
const span = document.querySelector('.close');

document.getElementById('placeOrderBtn')?.addEventListener('click', () => {
    if (cart.length === 0) return alert('السلة فارغة');
    cartPanel.style.display = 'none';
    modal.style.display = 'block';
});
span?.addEventListener('click', () => modal.style.display = 'none');
window.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });

/* 5) تحديد الموقع GPS */
document.getElementById('getLocationBtn')?.addEventListener('click', () => {
    if (navigator.geolocation) {
        alert('جارٍ تحديد موقعك...');
        navigator.geolocation.getCurrentPosition(pos => {
            document.getElementById('location').value = `GPS: ${pos.coords.latitude}, ${pos.coords.longitude}`;
        }, err => alert('تعذر الحصول على الموقع: ' + err.message));
    } else alert('المتصفح لا يدعم تحديد الموقع');
});

/* 6) تأكيد الطلب مع HMAC */
document.getElementById('confirmOrderBtn')?.addEventListener('click', async () => {
    const mobile = document.getElementById('mobile').value.trim();
    const location = document.getElementById('location').value.trim();
    const total = cart.reduce((s,i)=>s+i.price*i.qty,0);

    if (!/^\d{11}$/.test(mobile)) return alert('ادخل رقم هاتف صحيح مكون من 11 رقم');
    if (!location || location.length < 5) return alert('الرجاء إدخال موقع توصيل واضح ومفصل');

    try {
        const signRes = await fetch('/get_order_signature',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({total,mobile})
        });
        if(!signRes.ok){
            if(signRes.status===401) window.location.href='/login';
            return alert('خطأ في عملية التحقق الأمني.');
        }
        const signData = await signRes.json();
        if(!signData.signature || !signData.timestamp) return alert('خطأ: لم يتم الحصول على توقيع أمنى سليم.');

        const finalRes = await fetch('/place_order',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({total, cart, mobile, location, signature:signData.signature, timestamp:signData.timestamp})
        });
        const finalJson = await finalRes.json();
        alert(finalJson.message || (finalJson.success ? 'تم إرسال الطلب' : 'خطأ في إرسال الطلب'));
        if(finalJson.success){
            cart.length = 0;
            recalc();
            modal.style.display = 'none';
        } else if(finalRes.status===401) window.location.href='/login';
    } catch(e){ alert('حدث خطأ: '+e.message); }
});

/* 7) البحث */
document.getElementById('searchInput')?.addEventListener('input', e=>{
    const q = e.target.value.trim().toLowerCase();
    document.querySelectorAll('.product-card').forEach(card=>{
        const name = card.querySelector('.product-name')?.textContent.toLowerCase() || '';
        card.style.display = (!q || name.includes(q)) ? 'block' : 'none';
    });
});
