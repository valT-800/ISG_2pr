using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;

namespace Uzd_N2
{
    public partial class MainForm : Form
    {

        public MainForm()
        {
            InitializeComponent();
        }
        
        private void button1_Click_1(object sender, EventArgs e)
        {
            string encryptedText=" ";

            if (radioButton1.Checked==true)
                encryptedText = Repository.CBCEncryptStringToBytes(richTextBox1.Text, textBox2.Text);
            else if (radioButton2.Checked == true)
                encryptedText = Repository.ECBEncryptStringToBytes(richTextBox1.Text, textBox2.Text);
            else
                MessageBox.Show("Match the encrypting mode");
            richTextBox2.Text = encryptedText;

            StreamWriter f = new StreamWriter("encrypted.txt");
            f.WriteLine(encryptedText);
            f.Close();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            string encryptedText = File.ReadAllText("encrypted.txt");

            string decryptedData=" ";

            if (radioButton1.Checked==true) 
                decryptedData = Repository.CBCDecryptStringFromBytes(encryptedText, textBox2.Text);
            else if(radioButton2.Checked==true)
                decryptedData = Repository.ECBDecryptStringFromBytes (encryptedText, textBox2.Text);
            else
                MessageBox.Show("Match the encrypting mode");
            richTextBox2.Text = encryptedText;

            richTextBox1.Text = decryptedData;
        }
    }
}
