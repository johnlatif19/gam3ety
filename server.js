// استيراد المكتبات المطلوبة
require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const path = require('path');

// تهيئة التطبيق
const app = express();
const PORT = process.env.PORT || 3000;

// ==================== تهيئة Firebase ====================
// تحويل JSON من متغير البيئة
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);

// تهيئة Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
  projectId: firebaseConfig.projectId,
});

const db = admin.firestore();

// ==================== Middleware ====================
// أمان HTTP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://i.postimg.cc"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
    },
  },
}));

// CORS
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://gam3ety.vercel.app' : 'http://localhost:3000',
  credentials: true
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 100 // حد أقصى 100 طلب لكل IP
});
app.use('/api', limiter);

// معالجة JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// الملفات الثابتة
app.use(express.static(path.join(__dirname, 'public')));

// ==================== مساعدين (Helpers) ====================
// توليد JWT
const generateToken = (username) => {
  return jwt.sign(
    { username, role: 'admin' },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
};

// التحقق من JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'غير مصرح لك بالوصول' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'جلسة غير صالحة' });
  }
};

// ==================== التحقق من صحة البيانات (محدث) ====================
const validateMember = [
  body('name').trim().notEmpty().withMessage('الاسم مطلوب'),
  body('phone').trim().notEmpty().withMessage('رقم الهاتف مطلوب'),
  body('monthlyPayment').isNumeric().withMessage('المبلغ الشهري يجب أن يكون رقم'),
  body('gameyaValue').isNumeric().withMessage('قيمة الجمعية يجب أن تكون رقم'),
  body('paidAmount').isNumeric().withMessage('المبلغ المدفوع يجب أن يكون رقم'),
  body('remainingAmount').isNumeric().withMessage('المبلغ المتبقي يجب أن يكون رقم'),
  body('paidMonths').isInt({ min: 0 }).withMessage('الأشهر المدفوعة يجب أن تكون عدد صحيح'),
  body('remainingMonths').isInt({ min: 0 }).withMessage('الأشهر المتبقية يجب أن تكون عدد صحيح'),
  body('receiveAmount').isNumeric().withMessage('المبلغ المستلم يجب أن يكون رقم'),
  body('collectionOrder').trim().notEmpty().withMessage('دور الاستلام مطلوب'),
  body('collectionDate').trim().notEmpty().withMessage('تاريخ الاستلام مطلوب'),
  body('remainingName').trim().notEmpty().withMessage('المتبقي للاسم مطلوب'),
  body('status').trim().notEmpty().withMessage('الحالة مطلوبة'),
];

// ==================== Routes ====================
// الصفحة الرئيسية
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// صفحة تسجيل الدخول
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// لوحة التحكم
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// سياسة الخصوصية
app.get('/privacy-policy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy-policy.html'));
});

// ==================== API Routes ====================
// 1. تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // التحقق من البيانات
    if (!username || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    // التحقق من اسم المستخدم وكلمة المرور
    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPassword = process.env.ADMIN_PASSWORD;

    if (username !== adminUsername || password !== adminPassword) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    // توليد التوكن
    const token = generateToken(username);
    
    res.json({
      success: true,
      token,
      message: 'تم تسجيل الدخول بنجاح'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// 2. جلب عضو برقم الهاتف (عام)
app.get('/api/member/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
    // البحث في Firestore
    const membersRef = db.collection('members');
    const snapshot = await membersRef.where('phone', '==', phone).get();
    
    if (snapshot.empty) {
      return res.status(404).json({ error: 'لا يوجد عضو بهذا الرقم' });
    }

    let memberData = null;
    snapshot.forEach(doc => {
      memberData = { id: doc.id, ...doc.data() };
    });

    res.json(memberData);
  } catch (error) {
    console.error('Fetch member error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// 3. جلب جميع الأعضاء (محمي)
app.get('/api/members', verifyToken, async (req, res) => {
  try {
    const membersRef = db.collection('members');
    const snapshot = await membersRef.orderBy('createdAt', 'desc').get();
    
    const members = [];
    snapshot.forEach(doc => {
      members.push({ id: doc.id, ...doc.data() });
    });

    res.json(members);
  } catch (error) {
    console.error('Fetch members error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// 4. إضافة عضو جديد (محمي)
app.post('/api/member', verifyToken, validateMember, async (req, res) => {
  try {
    // التحقق من صحة البيانات
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const memberData = {
      ...req.body,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // إضافة للـ Firestore
    const docRef = await db.collection('members').add(memberData);
    const newMember = { id: docRef.id, ...memberData };

    res.status(201).json({
      success: true,
      member: newMember,
      message: 'تم إضافة العضو بنجاح'
    });
  } catch (error) {
    console.error('Add member error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// 5. تحديث عضو (محمي)
app.put('/api/member/:id', verifyToken, validateMember, async (req, res) => {
  try {
    // التحقق من صحة البيانات
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const updateData = {
      ...req.body,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // تحديث في Firestore
    await db.collection('members').doc(id).update(updateData);
    
    res.json({
      success: true,
      message: 'تم تحديث العضو بنجاح'
    });
  } catch (error) {
    console.error('Update member error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// 6. حذف عضو (محمي)
app.delete('/api/member/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // حذف من Firestore
    await db.collection('members').doc(id).delete();
    
    res.json({
      success: true,
      message: 'تم حذف العضو بنجاح'
    });
  } catch (error) {
    console.error('Delete member error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// 7. إحصائيات (محمي)
app.get('/api/stats', verifyToken, async (req, res) => {
  try {
    const membersRef = db.collection('members');
    const snapshot = await membersRef.get();
    
    let totalMembers = 0;
    let activeMembers = 0;
    let finishedMembers = 0;
    let totalCollections = 0;

    snapshot.forEach(doc => {
      const data = doc.data();
      totalMembers++;
      
      if (data.status === 'نشط') {
        activeMembers++;
      } else if (data.status === 'منتهي') {
        finishedMembers++;
      }
      
      totalCollections += data.receiveAmount || 0;
    });

    res.json({
      totalMembers,
      activeMembers,
      finishedMembers,
      totalCollections
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'حدث خطأ في الخادم' });
  }
});

// ==================== تشغيل الخادم ====================
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📍 http://localhost:${PORT}`);
  console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// معالجة الأخطاء العامة
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'حدث خطأ غير متوقع' });
});

module.exports = app;
