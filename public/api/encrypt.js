const crypto = require('crypto');

module.exports = (req, res) => {
  const { url, pass } = req.query;
  const ENCRYPTION_KEY = process.env.SECRET_KEY;

  if (!url || !pass || pass !== ENCRYPTION_KEY) {
    return res.status(403).send('Отказано в доступе: неверный пароль или нет ссылки');
  }

  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(url);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const keyParam = iv.toString('hex') + ':' + encrypted.toString('hex');
    const finalUrl = `https://${req.headers.host}/c?key=${keyParam}`;
    
    res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send(`
      
        Ваша зашифрованная ссылка:
        ${finalUrl}
      
    `);
  } catch (e) {
    res.status(500).send('Ошибка шифрования');
  }
};
