// Passive Frida probe: find which fd carries the JieLi RCSP transport.
//
// Attach to the official oraimo app and watch, WITHOUT sending anything:
//   frida -U -n "oraimo" -l tools/frida_rcsp_probe.js
//   (or drive it with tools/frida_capture.py, which saves an NDJSON capture)
//
// It hooks the libc socket calls only to READ the buffers the app already
// moves, and reports every buffer that carries the RCSP start marker
// (FE DC BA) together with its fd. The fd that keeps carrying valid frames is
// the SPP/RFCOMM-10 socket the app uses to talk to the headset. A second hook
// on the Java BluetoothSocket layer prints the fd of the RFCOMM connection as
// an independent cross-check.
//
// SAFETY: this script is strictly observational. It uses Interceptor.attach
// (never .replace), reads argument/return buffers in onEnter/onLeave, and
// calls no write/send/sendmsg/connect itself. It cannot make the app send a
// byte it would not otherwise send. This matches the project policy: we only
// observe what the official app does; the agent never opens RFCOMM 10, never
// authenticates, and never writes to it.

'use strict';

var MAGIC = [0xFE, 0xDC, 0xBA]; // RcspPacketParse start marker
var MAX_BYTES = 4096;           // cap per emitted buffer, keep the capture small
var startTime = Date.now();
var fdTarget = {};              // fd -> readlink target, resolved lazily

function ts() { return (Date.now() - startTime) / 1000.0; }

// readlink(/proc/self/fd/<fd>) so the report shows "socket:[inode]" etc.
var readlinkPtr = Module.findExportByName(null, 'readlink');
var readlink = readlinkPtr
  ? new NativeFunction(readlinkPtr, 'long', ['pointer', 'pointer', 'ulong'])
  : null;

function targetOf(fd) {
  if (fd in fdTarget) return fdTarget[fd];
  var t = null;
  if (readlink) {
    try {
      var path = Memory.allocUtf8String('/proc/self/fd/' + fd);
      var out = Memory.alloc(256);
      var n = readlink(path, out, 255);
      if (n > 0) t = out.readUtf8String(n);
    } catch (e) { /* ignore, target stays null */ }
  }
  fdTarget[fd] = t;
  return t;
}

// scan a buffer for the RCSP magic without copying the whole thing first
function findMagic(base, len) {
  var n = Math.min(len, MAX_BYTES);
  for (var i = 0; i + 3 <= n; i++) {
    if (base.add(i).readU8() === MAGIC[0] &&
        base.add(i + 1).readU8() === MAGIC[1] &&
        base.add(i + 2).readU8() === MAGIC[2]) {
      return true;
    }
  }
  return false;
}

function emit(fd, dir, base, len) {
  var n = Math.min(len, MAX_BYTES);
  if (n <= 0) return;
  if (!findMagic(base, n)) return; // only report RCSP-bearing buffers
  var bytes = base.readByteArray(n);
  send({
    t: ts(),
    fd: fd,
    dir: dir,
    target: targetOf(fd),
    hex: hex(bytes)
  });
}

function hex(arrayBuffer) {
  var u8 = new Uint8Array(arrayBuffer);
  var s = '';
  for (var i = 0; i < u8.length; i++) {
    var h = u8[i].toString(16);
    s += (h.length === 1 ? '0' : '') + h;
  }
  return s;
}

// ---- libc: write/send (tx, app -> headset) and read/recv (rx, headset -> app)
function hookWrite(name, fdArg, bufArg, lenArg) {
  var p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      var len = args[lenArg].toInt32();
      if (len > 0) emit(args[fdArg].toInt32(), 'tx', args[bufArg], len);
    }
  });
}

function hookRead(name, fdArg, bufArg) {
  var p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      this.fd = args[fdArg].toInt32();
      this.buf = args[bufArg];
    },
    onLeave: function (retval) {
      var n = retval.toInt32(); // bytes actually read
      if (n > 0 && this.buf) emit(this.fd, 'rx', this.buf, n);
    }
  });
}

hookWrite('write', 0, 1, 2);
hookWrite('send', 0, 1, 2);
hookRead('read', 0, 1);
hookRead('recv', 0, 1);

// sendmsg/recvmsg carry the payload in an iovec; walk the first iov entry,
// which is where BluetoothSocket's stream puts the RFCOMM data.
function iovFirst(msghdr) {
  // struct msghdr { void* name; socklen_t namelen; struct iovec* iov; size_t iovlen; ... }
  var ptrSize = Process.pointerSize;
  var iov = msghdr.add(ptrSize * 2).readPointer();       // msg_iov
  if (iov.isNull()) return null;
  var base = iov.readPointer();                            // iov_base
  var len = iov.add(ptrSize).readPointer().toInt32();     // iov_len
  return { base: base, len: len };
}

var sendmsgPtr = Module.findExportByName(null, 'sendmsg');
if (sendmsgPtr) {
  Interceptor.attach(sendmsgPtr, {
    onEnter: function (args) {
      var iov = iovFirst(args[1]);
      if (iov && iov.len > 0) emit(args[0].toInt32(), 'tx', iov.base, iov.len);
    }
  });
}

var recvmsgPtr = Module.findExportByName(null, 'recvmsg');
if (recvmsgPtr) {
  Interceptor.attach(recvmsgPtr, {
    onEnter: function (args) {
      this.iov = iovFirst(args[1]);
      this.fd = args[0].toInt32();
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0 && this.iov) emit(this.fd, 'rx', this.iov.base, Math.min(n, this.iov.len));
    }
  });
}

// ---- Java cross-check: which fd does the RFCOMM SPP connection use?
// This confirms the libc finding by reading the socket's own fd field. It only
// reads private fields; it does not call connect/write.
function hookJava() {
  if (!Java.available) return;
  Java.perform(function () {
    try {
      var BluetoothSocket = Java.use('android.bluetooth.BluetoothSocket');
      BluetoothSocket.connect.overload().implementation = function () {
        var result = this.connect(); // let the app's own connect run untouched
        try {
          var fd = -1;
          // Android keeps the fd behind ParcelFileDescriptor mPfd (newer) or
          // a LocalSocket mSocket (older). Try both, read-only.
          try {
            var pfd = this.mPfd.value;
            if (pfd !== null) fd = pfd.getFd();
          } catch (e1) {
            try { fd = this.mSocket.value.getFileDescriptor().getInt$(); } catch (e2) {}
          }
          send({
            t: ts(),
            java: 'BluetoothSocket.connect',
            fd: fd,
            target: fd >= 0 ? targetOf(fd) : null,
            note: 'RFCOMM SPP socket fd (Java cross-check)'
          });
        } catch (e) {
          send({ t: ts(), java: 'BluetoothSocket.connect', error: '' + e });
        }
        return result;
      };
    } catch (e) {
      send({ t: ts(), java: 'hook-failed', error: '' + e });
    }
  });
}

hookJava();
send({ t: ts(), info: 'rcsp probe attached (passive, read-only): watching for FE DC BA on all fds' });
