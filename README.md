# 👟 FootVogue - E-Commerce Platform

**FootVogue** is a feature-rich e-commerce platform built with **Django** and **PostgreSQL**, tailored for footwear shopping. It offers a seamless user experience with OTP authentication, wallet payments, order tracking, real-time stock control, and a powerful admin dashboard.

---

## 🚀 Features

- 🔐 **User Authentication** – Sign up/login with OTP & email verification  
- 🛒 **Smart Cart System** – Add, remove, update quantity of items  
- 💳 **Payment Integration** – Razorpay & wallet-based transactions  
- 🧾 **Stock & Order Management** – Real-time inventory, refunds & returns  
- 🎁 **Coupons & Offers** – Promo codes, referral rewards & discounts  
- 📈 **Admin Dashboard** – View sales reports, manage products/orders  
- 👛 **Wallet System** – Store refunds, referral rewards, and manage transactions  
- 🔍 **Search & Filters** – Sort by price, rating, new arrivals, in-stock  
- 📱 **Mobile Responsive** – Clean UI for all screen sizes

---

## 🛠️ Technologies Used

- **Backend**: Django, Django-Allauth, PostgreSQL  
- **Frontend**: HTML, CSS, JavaScript, Bootstrap  
- **Payments**: Razorpay Integration  
- **Authentication**: OTP, Email, Social Login  
- **Deployment**: AWS EC2, Gunicorn, Nginx  
- **Static & Media Files**: Managed using `collectstatic`, served via Nginx  
- **Security**: HTTPS via Let’s Encrypt SSL  

---

## 📁 Project Structure

```
footvogue/
├── footvogueapp/             # Core Django app
│   ├── models.py             # Product, Order, Wallet models
│   ├── views.py              # Business logic
│   ├── templates/            # HTML templates
│   ├── static/               # CSS, JS, images
│   └── urls.py               # App-level routes
├── media/                    # Uploaded images
├── manage.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation Guide

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/HibahMohammedK/footvogue.git
cd footvogue
```

### 2️⃣ Set Up Virtual Environment

```bash
python3 -m venv env
source env/bin/activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Configure the Database in `settings.py`

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'your_db_name',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### 5️⃣ Apply Migrations & Create Superuser

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### 6️⃣ Run the Server

```bash
python manage.py runserver
```

---

## 🌐 Deployment Overview (AWS EC2)

- Ubuntu 20.04 EC2 instance  
- **Gunicorn** for WSGI application  
- **Nginx** for reverse proxy & serving static/media files  
- **Let’s Encrypt SSL** for HTTPS  

---

## 🛠 Admin Panel

Access via `/admin/` with superuser credentials.

Admin can manage:
- ✅ Products & Variants  
- ✅ Orders, Returns & Refunds  
- ✅ Coupons & Offers  
- ✅ Wallet Balances & Transactions  
- ✅ Sales Reports & Analytics  

---

## 📊 Future Improvements

- 📦 Integrate delivery partners (e.g., ShipRocket)  
- 📧 Email alerts for orders, status updates, and refunds  
- 🌍 Support for multiple languages and currencies  
- 🔔 Push notifications and tracking updates  

---

## 🙋‍♀️ Author

**Hibah Mohammed**  
📍 Abu Dhabi, UAE  
📧 hibahmohammedk@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/hibahmohammed) *(Add your LinkedIn if available)*  

---

## 📃 License

This project is licensed under the [MIT License](LICENSE).

---

> 💡 _Have ideas to improve FootVogue? Contributions are welcome!_
