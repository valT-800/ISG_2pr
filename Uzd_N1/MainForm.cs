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

        private readonly Repository repository = new Repository();
        public MainForm()
        {
            InitializeComponent();
        }
        
        private void button1_Click_1(object sender, EventArgs e)
        {
            //var plaintext = ByteConverter.GetBytes(richTextBox1.Text);
            //var encryptedtext = repository.Encryption(plaintext, RSA.ExportParameters(false), false);
            var encryptedText = repository.Encryption(richTextBox1.Text);
            richTextBox2.Text = encryptedText;
            //richTextBox2.Text = ByteConverter.GetString(encryptedtext);
            
        }

        private void button2_Click(object sender, EventArgs e)
        {
            //var encryptedtext = ByteConverter.GetBytes(richTextBox2.Text);
            //byte[] decryptedtext = repository.Decryption(encryptedtext, RSA.ExportParameters(true), false);
            var decryptedText = repository.Decryption(richTextBox2.Text);
            richTextBox1.Text = decryptedText;
            //richTextBox1.Text = ByteConverter.GetString(decryptedtext);

        }
    }
}
