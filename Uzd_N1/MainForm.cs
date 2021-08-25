using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;


namespace Uzd_N3
{
    public partial class MainForm : Form
    {
        private readonly UnicodeEncoding ByteConverter = new UnicodeEncoding();
        private readonly RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
        string fileName = "encrypted.txt";
        private readonly RSA rsa = new RSA();
        public MainForm()
        {
            InitializeComponent();
        }
        
        private void encryptButton_Click(object sender, EventArgs e)
        {
            var plainText = ByteConverter.GetBytes(richTextBox1.Text);
            var encryptedText = rsa.Encryption(plainText, RSA.ExportParameters(false), false);
            richTextBox2.Text = Convert.ToBase64String(encryptedText, Base64FormattingOptions.InsertLineBreaks);
            
        }

        private void decryptButton_Click(object sender, EventArgs e)
        {

        }
    }
}
