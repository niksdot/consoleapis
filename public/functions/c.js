// Вспомогательная функция для безопасного отображения HTML (защита от XSS)
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Декодирование Base64URL в Uint8Array
function base64UrlDecode(base64Url) {
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const raw = atob(base64);
  const result = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    result[i] = raw.charCodeAt(i);
  }
  return result;
}

// Функция расшифровки AES-256-GCM
async function decrypt(encryptedBase64Url, secretKeyString) {
  const encoder = new TextEncoder();
  // Для AES-256 ключ должен быть ровно 32 байта. Дополняем или обрезаем строку.
  const keyData = encoder.encode(secretKeyString.padEnd(32, '0').slice(0, 32));

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const data = base64UrlDecode(encryptedBase64Url);
  
  // В AES-GCM вектор инициализации (IV) обычно занимает первые 12 байт
  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// Основной обработчик запроса
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const keyParam = url.searchParams.get('key');

  if (!keyParam) {
    return new Response('Ошибка: параметр key не найден', { status: 400 });
  }

  try {
    // Берем секретный ключ из переменных окружения
    const secretKey = env.SECRET_KEY;
    if (!secretKey) throw new Error("SECRET_KEY не настроен");

    // Расшифровываем ссылку
    const decryptedUrl = await decrypt(keyParam, secretKey);
    const safeUrl = escapeHtml(decryptedUrl);

    // Генерируем HTML с кнопкой Go
    const html = `
      <!DOCTYPE html>
      <html lang="ru">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Переход по защищенной ссылке</title>
        <style>
          body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f4f4f5; margin: 0; }
          .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); text-align: center; max-width: 400px; width: 100%; }
          .url-box { margin: 1.5rem 0; padding: 1rem; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; word-break: break-all; color: #334155; }
          a.btn { display: inline-block; padding: 12px 32px; background: #2563eb; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; transition: background 0.2s; }
          a.btn:hover { background: #1d4ed8; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Секретная ссылка</h2>
          <p>Нажмите кнопку ниже, чтобы перейти по расшифрованному адресу:</p>
          <div class="url-box">${safeUrl}</div>
          <a href="${safeUrl}" class="btn" rel="noopener noreferrer">Go ➔</a>
        </div>
      </body>
      </html>
    `;

    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  } catch (err) {
    return new Response(`Детали ошибки: ${err.message}`, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
    });
  }
}
