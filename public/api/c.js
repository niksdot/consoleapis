const crypto = require('crypto');

module.exports = (req, res) => {
  const key = req.query.key;

  if (!key) {
    return res.status(400).send('Ошибка: Ключ не предоставлен.');
  }

  try {
    const ENCRYPTION_KEY = process.env.SECRET_KEY;
    if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
      return res.status(500).send('Ошибка сервера: Неверный SECRET_KEY.');
    }

    const textParts = key.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const decryptedUrl = decrypted.toString();

    const html = `
      
      
      
        
        
        Секретная ссылка
      
      
        Секретная ссылка
        Ссылка успешно расшифрована:
        
          ${decryptedUrl}
        
        
          
            Перейти (Go)
          
        
      
      
    `;
    res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send(html);
  } catch (error) {
    return res.status(400).send('Ошибка: Не удалось расшифровать ссылку.');
  }
};
