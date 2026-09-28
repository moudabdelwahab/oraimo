# بروتوكول JieLi RCSP من تطبيق oraimo (تحليل ثابت)

المصدر: كود مفكوك بـ jadx من `classes2.dex` في تطبيق oraimo Sound (`com.transsion.oraimosound`). الأصناف المقروءة حتى الآن:

- `com.jieli.bluetooth.tool.handler.RcspPacketParse`
- `com.jieli.bluetooth.utils.CommandBuilder`
- `com.jieli.bluetooth.tool.spp.ConnectionSppThread`
- `com.jieli.bluetooth.utils.CHexConver`
- `com.jieli.bluetooth.tool.ParseHelper`
- `com.jieli.bluetooth.bean.base.CommandBase`
- `com.jieli.bluetooth.bean.parameter.SetSysInfoParam`
- `com.jieli.bluetooth.impl.RcspAuth`
- `com.jieli.bluetooth.impl.BluetoothSpp`
- `com.bluetrum.devicemanager.cmd.request.KeyRequest`

> **الحالة: كل ما هنا في فئة «محتمل».** هذا الكود هو ما يفعله التطبيق، وليس ما رصدناه على السماعة. لا ينتقل أي بند إلى «مؤكد» إلا بالتقاط حقيقي لقناة RFCOMM 10. لا يرسل الوكيل أي شيء إلى هذه القناة، ولن يرسل.

---

## 1. إطار الحزمة (من `RcspPacketParse`، جهة الاستقبال)

```
FE DC BA | FLAG | OPCODE | LEN (2 بايت) | PAYLOAD (LEN بايت) | EF
```

| الحقل | الحجم | الدليل في الكود |
|---|---|---|
| البداية | 3 | `c = {-2, -36, -70}` = `FE DC BA` |
| FLAG | 1 | `bArr[0]`: بت «النوع» و«يحتاج ردًا» (القسم 2) |
| OPCODE | 1 | `bArr[1]` |
| LEN | 2 | `bytesToInt(bArr, 2, 2)` ← `((b0 & 0xFF) << 8) + (b1 & 0xFF)`، أي **big-endian** (من `CHexConver`) |
| PAYLOAD | LEN | طوله يساوي LEN بالضبط |
| النهاية | 1 | `bArr[... + 4 + LEN] == -17` = `EF` |

- **لا يوجد checksum ولا CRC** في هذا الإطار. التحقق الوحيد هو وجود `FE DC BA` في البداية، و`EF` في موضعه حسب LEN. سلامة البيانات تعتمد على RFCOMM نفسه.
- حجم الإطار الإضافي 8 بايتات (3 + 1 + 1 + 2 + 1)، ويطابق فحص الكود `LEN > mtu - 8` الذي يرمي الإطار.
- الحزم الناقصة تُحفظ في مخزن مؤقت، وتُدمج مع البيانات التالية.
- جهة الإرسال تأكدت الآن في `ParseHelper.packSendBasePacket`: نفس الغلاف `FE DC BA … EF`، نفس الطول big-endian (`int2byte2`)، **ولا checksum يُضاف عند الإرسال أيضًا**. فبنية الإطار في الاتجاهين واحدة.

> **مطبَّق في الوكيل (قراءة فقط):** يفكّ `agent/sniffer.py` هذا الغلاف سلبيًا من ملفات الالتقاط (`rcsp_extract`/`decode_rcsp_frame`): البداية والعلَم (النوع + يحتاج ردًا) والرمز والطول والرقم التسلسلي و`XM_OPCODE` و`STATUS`، مع إعادة تجميع الإطارات المجزأة. محتوى `DATA` يبقى خامًا لأن جدول الرموز وصيغة `AttrBean` مجهولان. تُعرض النتيجة في صفحة «التحكم المتقدم». لا يفتح المحلّل قناة ولا يرسل بايتًا.

## 2. محتوى الـ PAYLOAD

| الحالة | البنية |
|---|---|
| رد (type = 0) | `STATUS(1) SN(1) [XM_OPCODE(1) إذا OPCODE = 0x01] DATA…` |
| أمر أو إشعار (type = 1) | `SN(1) [XM_OPCODE(1) إذا OPCODE = 0x01] DATA…` |

- `getBooleanArrayBig(b)` يضع البت رقم i في الموضع i، بدءًا من البت الأدنى (من `CHexConver`). لذلك:
  - **bit7 من FLAG = النوع:** 1 أمر أو إشعار، و0 رد.
  - **bit6 من FLAG = يحتاج ردًا.**
  - البتات 0–5 لا يقرؤها المحلل.
  - مثال محسوب من الكود وليس مرصودًا: أمر يحتاج ردًا يكون FLAG فيه `0xC0`، وردّ عليه يكون `0x00`.
- `SN` رقم تسلسلي يربط الطلب بالرد (`SnGenerator`).
- `OPCODE = 0x01` هو أمر البيانات `DataCmd`، ويحمل `XM_OPCODE` إضافيًا.

## 3. نموذج الأوامر (من `CommandBuilder`)

`CommandBuilder` يبني كائنات فقط. رقم الأمر (`opCode`) ونوعه (`type`) مخزنان في `CommandBase`، والتطبيق يوجّه كل حزمة واردة عبر خريطة `Command.getValidCommandList()` حسب الـ opCode. لذلك **جدول أرقام الأوامر كامل موجود في صنف الثوابت `com.jieli.bluetooth.constant.Command`**، ولم يُقرأ بعد. المعروف حتى الآن: `DataCmd` = 0x01، و`PushStartTtsCmd` = 0x11.

قيم `type` في `CommandBase` (تحدد بتات FLAG عند الإرسال في `packSendBasePacket`): 0 لا معامل + رد، 1 معامل بلا رد، 2 معامل + رد، 3 لا معامل + رد. عند الإرسال يُضبط bit7 إذا كان الاتجاه أمرًا، وbit6 إذا كان النوع 2 أو 3 (أي ينتظر ردًا).

### 3.1 GetSysInfo / SetSysInfo: قراءة الخصائص وكتابتها

`GetSysInfoCmd(function, mask)` و`SetSysInfoCmd(function, [AttrBean(type, data)…])`

قيم `function`:

| القيمة | المجال |
|---|---|
| `0xFF` (‎-1) | عام (Public) |
| `0` | Bluetooth |
| `1` | الموسيقى |
| `2` | RTC / المنبه |
| `3` | AUX |
| `4` | FM |
| `8` | SPDIF |
| `9` | PC slave |

في المجال العام، رقم البت في `mask` يساوي رقم `type` في `AttrBean`. تكرر هذا التطابق في كل الحالات الظاهرة، مثل volume (bit1 ↔ type1) وEQ (bit4 ↔ type4) وhigh/bass (bit11 ↔ type11) وvoice mode (bit13 ↔ type13):

| البت/النوع | الخاصية | صيغة الكتابة في الكود |
|---|---|---|
| 0 | البطارية | قراءة فقط |
| 1 | الصوت | بايت واحد |
| 2 | معلومات الجهاز | قراءة فقط |
| 3 | خطأ | بايت واحد |
| 4 | EQ | قديمة: `mode + 10 قيم`. جديدة: `mode|0x80, count, values…` |
| 5 | نوع ملفات التصفح | `len + ascii` |
| 7 | الإضاءة | بايتات خام |
| 8 | تردد إرسال FM | — |
| 9 / 10 | وضع المُرسِل / حالته | — |
| 11 | الترددات العالية + الجهير | 8 بايت: عددان صحيحان big-endian (الوسيط الثاني أولًا) |
| 12 | قيم EQ المسبقة | قراءة (mask 4096) |
| 13 | الوضع الصوتي الحالي (ANC/شفافية مرجّحًا) | `VoiceMode.getBytes()` |
| 14 | كل الأوضاع الصوتية | قراءة |
| 16 | بيانات بطول ثابت | `int + data` |
| 17–18 / 19 | EQ بطاقة الصوت / معلوماتها | — |
| 20 | مساعد السمع | — |
| 21 | التكيف (Adaptive) | — |
| 22 | Smart No-Pick | — |
| 23 | تقليل الضوضاء حسب المشهد | — |
| 24 | كشف الرياح | — |
| 25 | Vocal Booster | — |

`SetSysInfoParam.getParamData()` صار معروفًا: بايت `function`، يتبعه لكل خاصية ناتج `AttrBean.toData()` متسلسلًا. أما ترتيب البايتات داخل `AttrBean.toData()` نفسه (نوع/طول/بيانات) فما زال **غير معروف** حتى يُقرأ `AttrBean`.

### 3.2 FunctionCmd(function, op, extend)

| function | op |
|---|---|
| 1 (موسيقى BT) | 1 تشغيل/إيقاف مؤقت، 2 السابق، 3 التالي، 4 وضع التشغيل التالي، 5 وضع EQ التالي، 6 ترجيع (short)، 7 تقديم (short) |
| 0 (ID3) | 1 تشغيل/إيقاف مؤقت، 2 السابق، 3 التالي، 4 تفعيل إرسال ID3 |
| 4 (FM) | 1–9 |
| 0xFF | تبديل الوضع: 0 BT، 1 موسيقى، 2 RTC، 3 Line-in، 4 FM |

ملاحظة: `buildRestoreCmd(b)` يستخدم `(0, 1, [b])`، أي نفس `function/op` الخاص بـ ID3 play/pause لكن مع بايت إضافي. الاسم لا يعني «إعادة ضبط المصنع».

### 3.3 أوامر خطرة (لن تُنفَّذ أبدًا)

- `RebootDeviceCmd`: ‏0 = إعادة تشغيل، 1 = **إيقاف تشغيل**.
- `CustomCmd(bytes)`: أمر بايتات خام. يُرجّح أن أوامر oraimo الخاصة، مثل `Key*Request` و`FactoryResetRequest`، تمر عبره أو عبر طبقة Bluetrum، ولم يُتحقق من ذلك.
- `SetDevStorageCmd` وأوامر نقل الملفات وكل أصناف OTA.

## 3.4 ترميز القيم (من `CHexConver`)

- الأعداد في الأوامر big-endian: `intToBigBytes` و`shortToBigBytes`. توجد أيضًا دوال little-endian (`intToLittleBytes` و`bytesLittleToInt`)، وتُستخدم في مواضع أخرى لم تُحدَّد بعد.
- النصوص تُرمَّز بـ **GBK** وليس UTF-8 (`str2HexStr` و`hexStr2ASCII`).
- العناوين تُرسل 6 بايت بترتيب النص نفسه: `28:52:E0:…` ← `28 52 E0 …`.

## 4. الاتصال (من `ConnectionSppThread` و`BluetoothSpp`)

- الاتصال يتم بـ `createRfcommSocketToServiceRecord(uuid)`. أي أن Android يبحث عن الـ UUID في SDP ويختار القناة منه، وهي في حالة سماعتنا `fe010000-…` ← RFCOMM 10 (SDP في الالتقاط).
- الـ UUID يأتي من `BluetoothOption.getSppUUID()`، أي **يُضبط عند تهيئة المكتبة** ولا يظهر ثابتًا هنا. أول ما تصل قيمته الفعلية من صنف التهيئة نضيفه.
- إذا لم يجد التطبيق الـ UUID في الجهاز، يكتب تحذيرًا في السجل فقط ويكمل. الكتابة الفعلية عبر `writeDataToSppDevice` → `socket.getOutputStream().write()`.

## 5. القناة مصادَق عليها (من `RcspAuth`) — أهم نتيجة أمنية

قبل أن تقبل السماعة أوامر التحكم، هناك **مصادقة تحدٍّ-واستجابة** منطقها كله داخل مكتبة native مغلقة المصدر:

- `RcspAuth` يستدعي `System.loadLibrary` ثم دوال JNI: `nativeInit`، `getRandomAuthData`، `getEncryptedAuthData`، و`setLinkKey`.
- المصادقة **مربوطة بمفتاح ارتباط BR/EDR** للجهاز (`setDeviceConnectionLinkKey` → `setLinkKey`). أي أنها خاصة بكل زوج هاتف/سماعة.
- الحساب يجري في الكود الأصلي (native)، ولا يمكن إعادة إنتاجه من كود Java وحده.

**الخلاصة:** قناة JieLi ليست «افتح المقبس وأرسل بايتات». الأمر يتطلب مصافحة مصادقة بمفتاح خاص بجهازك محسوبة في مكتبة مغلقة. هذا يعزز سياسة المشروع: **الوكيل لا يفتح RFCOMM 10 ولا يكتب إليه ولا يصادِق عليه.** لن يُوثَّق في هذا المستند تسلسل المصافحة ولا أي بايتات قابلة للإعادة.

## 6. عائلة أوامر ثانية: Bluetrum (من `KeyRequest`)

إلى جانب إطار JieLi، يحتوي التطبيق على طبقة `com.bluetrum.devicemanager` بإطارها المستقل (`Command`/`Request` ولها `getPayload()` و`commandId` خاص بها). مثال `KeyRequest`:

- **الغرض:** تخصيص وظيفة كل إيماءة زر (يسار/يمين، ضغطة/مزدوجة/ثلاثية/مطوّلة).
- **الوظائف المتاحة (ثوابت):** بلا، استرجاع، مساعد، سابق، تالي، رفع/خفض الصوت، تشغيل/إيقاف، وضع اللعب، وضع ANC. إضافة إلى حساسية اللمس (منخفضة/عادية/عالية).

هذه العائلة إثبات إضافي على أن الأزرار قابلة لإعادة التعيين، لكنها **عائلة مختلفة** عن `RcspPacketParse`، ولا نعرف أي العائلتين تستخدمها Necklace Lite فعليًا. تبقى في «محتمل».

## 7. ما زال مجهولًا، والملفات المطلوبة لسده

| المجهول | الصنف المطلوب من jadx |
|---|---|
| جدول أرقام OPCODE الكامل | `com.jieli.bluetooth.constant.Command` |
| صيغة AttrBean على السلك | `com.jieli.bluetooth.bean.base.AttrBean` (‏`toData()`) |
| قيمة الـ UUID الفعلية | صنف تهيئة `BluetoothOption` ومن يستدعي `setSppUUID` |
| إطار Bluetrum الكامل | `com.bluetrum.devicemanager.cmd.Command` و`Request` |
| أي العائلتين تخص السماعة | يحتاج التقاطًا حقيقيًا؛ لا يُحسم من الكود |
