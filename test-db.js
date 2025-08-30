const mysql = require('mysql2/promise');

async function testConnection() {
  try {
    const connection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'P@55word',
      database: 'ucc_chain_test'
    });

    console.log('✅ Connected to MySQL successfully!');
    
    // Test query
    const [rows] = await connection.execute('SELECT 1 as test');
    console.log('✅ Test query successful:', rows[0]);
    
    // Test contracts table
    const [tables] = await connection.execute('SHOW TABLES');
    console.log('✅ Available tables:', tables);
    
    await connection.end();
    console.log('✅ Connection closed successfully');
    
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
  }
}

testConnection();