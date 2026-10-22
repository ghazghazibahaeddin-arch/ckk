# CCK — Command & Control Kit
### منصة موثوقية وتحكم لأفعال وكلاء الذكاء الاصطناعي الخارجية
**Reliability, Governance, and Control Platform for External AI Agent Actions**

---

## 📌 نبذة عن المشروع / Overview

مشروع **CCK** هو منصة تحكم وموثوقية هندسية مصممة لاعتراض، وفحص، وتدقيق أفعال وكلاء الذكاء الاصطناعي (AI Agents) قبل وأثناء تفاعلها مع العالم الخارجي (أوامر الطرفية Bash، استعلامات قواعد البيانات، استدعاءات الـ APIs، والعمليات على أنظمة الملفات).

يهدف المشروع إلى توفير:
1. **بوابة تحكم موحدة (Control Plane Gateway):** تفحص أي فعل صادر من أي وكيل بناءً على عقود بيانات صارمة وموحدة.
2. **محرك سياسات وحواجز أمان (Policy & Guardrails Engine):** يصدر أحكامًا ملزمة (`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`).
3. **سجل تدقيق مشفر وغير قابل للتلاعب (Cryptographic Audit Trail):** يربط كل فعل وكل حكم في سلسلة هاش متصلة تضمن إمكانية التحقق والتتبع التام.
4. **تجريد حدود التخزين (Storage Boundary):** دعم كامل لـ SQLite للتطوير المحلي مع جاهزية معمارية للانتقال إلى PostgreSQL.
5. **واجهات تشغيل مزدوجة:** واجهة سطر أوامر تفاعلية (CLI) مبنية بـ Typer وRich، وواجهة برمجية سريعة (HTTP REST API) مبنية بـ FastAPI.

---

## 🏛️ المعمارية الهندسية (Modular Monolith Architecture)

تم اعتماد معمارية **المونو الدائري المنظم (Modular Monolith)** لتحقيق أقصى درجات الأداء والموثوقية وتجنب تعقيدات الخدمات الموزعة غير الضرورية:

```
src/cck/
├── __init__.py           # تعريف الإصدار وتصدير المكونات الأساسية
├── core/                 # النواة المشتركة: الأنواع، الإعدادات، السجلات، الاستثناءات
│   ├── config.py         # إعدادات Pydantic Settings مع دعم متغيرات البيئة
│   ├── exceptions.py     # شجرة استثناءات صريحة (CCKError, StorageError, ...)
│   ├── logging.py        # تسجيل منظم للمعلومات والأحداث
│   └── types.py          # Enums الأساسية (VerdictDecision, RiskLevel, ...)
├── contracts/            # عقود البيانات الصارمة المعتمدة على Pydantic v2
│   ├── action.py         # نموذج AgentAction و AgentIdentity
│   ├── verdict.py        # نموذج ExecutionVerdict و PolicyMatch
│   ├── policy.py         # نموذج PolicyRule والاشتراطات
│   ├── audit.py          # نموذج AuditRecord وسلسلة الهاش
│   ├── entity.py         # نموذج Entity والتحقق الصارم من المعرفات
│   ├── fact.py           # نموذج Fact وبصمة الحقل ودعم حالات الصلاحية
│   ├── evidence.py       # نموذج Evidence والأدلة المولدة نظاميًا
│   ├── dependency.py     # نماذج DependencyNode و ActionDependencySpec
│   ├── journal.py        # نموذج JournalEntry وسلسلة التجزئة للتدقيق
│   └── contract_def.py   # نموذج ContractDefinition وإصدارات العقود
├── reliability/          # محرك الموثوقية الأساسي (Layer 1: Core Reliability Engine)
│   ├── entity_registry.py   # سجل الكيانات ومنع خلط الأسماء المتشابهة
│   ├── evidence_registry.py # سجل الأدلة المولدة من النظام حصراً (System-Minted)
│   ├── fact_registry.py     # سجل الحقائق والتحقق من الإصدارات وتقادم الـ TTL
│   ├── dependency_graph.py  # رسم بياني للاعتماديات وكشف الحلقات الدائرية (Cycle Detection)
│   ├── freshness_engine.py  # محرك الحداثة والبصمات الدقيقة وتجنب الإبطال العشوائي
│   ├── action_gate.py       # بوابة الأفعال المركزية (Zero-Bypass Action Gate)
│   ├── journal.py           # سجل الأحداث غير القابل للتلاعب المتسلسل
│   ├── replay_engine.py     # محرك إعادة التشغيل المعزول دون أي كتابة خارجية
│   └── contract_registry.py # سجل العقود وفحص التوافقية ورفض الإصدارات الملغاة
├── storage/              # طبقة التخزين والتجريد
│   ├── base.py           # واجهة التخزين المجردة StorageBackend (Protocol)
│   ├── schema.py         # مخططات DDL لـ SQLite وخريطة الانتقال لـ PostgreSQL
│   └── sqlite.py         # التنفيذ غير المتزامن المعتمد على aiosqlite
├── policies/             # محرك فحص السياسات والقواعد المعيارية
│   └── engine.py         # فحص الأوامر المدمرة، المسارات الحساسة، والحاجة للموافقة
├── audit/                # إدارة سجلات التدقيق وسلاسل النزاهة
│   └── service.py        # حساب SHA-256 والتحقق من سلامة السلسلة
├── runtime/              # محرك التشغيل الرئيسي
│   └── engine.py         # CCKControlPlane الجامع للسياسات والتخزين والتدقيق
├── api/                  # واجهة الويب REST API
│   └── app.py            # تطبيق FastAPI ومسارات الفحص والصحة والسياسات
└── cli/                  # واجهة سطر الأوامر
    └── main.py           # أوامر Typer (info, init-db, inspect-action, run-server)
```

---

## 🚀 التثبيت والتشغيل / Getting Started

### 1. المتطلبات الأساسية
- Python 3.10 أو أحدث.
- أداة `uv` لإدارة البيئة الافتراضية والتبعيات (أو `pip`).

### 2. تجهيز البيئة الافتراضية وتثبيت التبعيات
```bash
# إنشاء البيئة الافتراضية
uv venv .venv --python 3.10

# تفعيل البيئة (Linux/macOS)
source .venv/bin/activate

# تثبيت الحزمة والتبعيات التطويرية
uv pip install -e ".[dev]"
```

---

## 🧪 أوامر الاختبار والفحص / Testing & Linting

تم إعداد بيئة اختبار شاملة تغطي 58 اختبارًا لوحدات التأسيس ومحرك الموثوقية الأساسي (Layer 1)، بما فيها سيناريو القبول الإلزامي (إبطال حالة الطلب وتحول القرار إلى BLOCK):

```bash
# تشغيل جميع الاختبارات (58 اختبارًا)
.venv/bin/pytest -v

# تشغيل اختبارات القبول الإلزامية لطبقة الموثوقية فقط
.venv/bin/pytest -v tests/integration/test_acceptance_scenarios.py

# فحص التنسيق والأنماط البرمجية باستخدام ruff
.venv/bin/ruff check .
```

---

## 💻 استخدام واجهة سطر الأوامر (CCK CLI)

توفر أداة `cck` إمكانية فحص النظام والتحقق من سيناريوهات الأفعال مباشرة:

```bash
# عرض معلومات البيئة وحالة منصة التحكم
.venv/bin/python -m cck.cli.main info

# تهيئة قاعدة بيانات SQLite وتحميل سياسات الأمان المعيارية
.venv/bin/python -m cck.cli.main init-db

# فحص سيناريو أمر مدمر (مثل rm -rf /) ورؤية قرار المنع الفوري
.venv/bin/python -m cck.cli.main inspect-action scenarios/destructive_command_scenario.json

# فحص سيناريو تعديل نظام يتطلب موافقة بشرية
.venv/bin/python -m cck.cli.main inspect-action scenarios/system_mutation_scenario.json

# تشغيل خادم الـ API عبر سطر الأوامر
.venv/bin/python -m cck.cli.main run-server --port 8000
```

---

## 🌐 واجهة الويب البرمجية (REST API)

يمكن تشغيل خادم FastAPI مباشرة:

```bash
.venv/bin/uvicorn cck.api.app:app --host 0.0.0.0 --port 8000
```

### أهم المسارات (Endpoints):
- `GET /health` : فحص حالة الخادم وجاهزية المكونات.
- `GET /api/v1/info` : عرض إحصائيات المنصة، عدد السياسات الفعالة، ونوع التخزين.
- `POST /api/v1/actions/evaluate` : استقبال كائن `AgentAction` وإرجاع حكم `ExecutionVerdict`.
- `GET /api/v1/policies` : عرض قائمة السياسات وحواجز الأمان المفعلة.
- `GET /api/v1/audits` : تصفح سجل التدقيق المشفر بالتسلسل الزمني.

---

## 📁 المجلدات التوثيقية والسيناريوهات
- `docs/architecture_decisions.md`: سجل قرارات المعمارية الأساسية (ADR-001 إلى ADR-004).
- `docs/contracts_and_schemas.md`: توثيق مواصفات البيانات وعقود النماذج.
- `scenarios/`: نماذج وسيناريوهات جاهزة لاختبار أفعال الوكلاء (آمنة، مدمرة، حرجة).
- `tests/`: جناح الاختبارات الوحدوية والتكاملية لجميع الطبقات.

---

## ⚖️ معيار القبول ورسالة المرحلة الحالية
تم تأسيس الهيكل الهندسي، وحزم التبعيات، وتجريد التخزين، وعقود البيانات، ومحرك القواعد الأولي، مع اجتياز كامل للاختبارات دون أخطاء. ولم يتم التوسع خارج نطاق مرحلة التأسيس حتى يتم اعتمادها.
