using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;


namespace Uzd_N2
{
    public partial class MainForm : Form
    {
        private readonly UnicodeEncoding ByteConverter = new UnicodeEncoding();
        private readonly RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
        private byte[] plaintext;
        private byte[] encryptedtext;

        private readonly Repository repository = new Repository();
        public MainForm()
        {
            InitializeComponent();
        }
        
        private void button1_Click_1(object sender, EventArgs e)
        {
            plaintext = ByteConverter.GetBytes(richTextBox1.Text);
            encryptedtext = repository.Encryption(plaintext, RSA.ExportParameters(false), false);
            richTextBox2.Text = ByteConverter.GetString(encryptedtext);
            
        }

        private void button2_Click(object sender, EventArgs e)
        {
            byte[] decryptedtex = repository.Decryption(encryptedtext, RSA.ExportParameters(true), false);
            richTextBox1.Text = ByteConverter.GetString(decryptedtex);
        }
    }
}
