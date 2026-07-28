import crypto from 'crypto';

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&")
    .replace(//g, ">")
    .replace(/"/g, """)
    .replace(/'/g, "'");
}

export default function handler(req, res) {
  const keyParam = req.query.key;

  if (!keyParam) {
    return res.status(400).send('Ошибка: параметр key не найден');
  }

  try {
    const secretKeyString = process.env.SECRET_KEY;
    if (!secretKeyString) throw new Error("SECRET_KEY не настроен");

    // Подготавливаем ключ (ровно 32 байта)
    const key = Buffer.from(secretKeyString.padEnd(32, '0').slice(0, 32));

    // Декодируем Base64URL обратно в Buffer
    const base64 = keyParam.replace(/-/g, '+').replace(/_/g, '/');
    const data = Buffer.from(base64, 'base64');

    // Разбираем буфер на части (по формату нашего генератора)
    const iv = data.subarray(0, 12);
    const authTag = data.subarray(data.length - 16);
    const ciphertext = data.subarray(12, data.length - 16);

    // Расшифровываем
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decryptedUrl = decipher.update(ciphertext, undefined, 'utf8');
    decryptedUrl += decipher.final('utf8');

    const safeUrl = escapeHtml(decryptedUrl);

    // Генерируем HTML
    const html = `
      
      
      
        
        
        Переход по защищенной ссылке
        
      
      
        
          Секретная ссылка
          Нажмите кнопку ниже, чтобы перейти по расшифрованному адресу:
          ${safeUrl}
          Go ➔
        
      
      
    `;

    res.setHeader('Content-Type', 'text/html;charset=UTF-8');
    res.status(200).send(html);
  } catch (err) {
    res.status(403).send('Ошибка: неверный или поврежденный ключ.');
  }
}
