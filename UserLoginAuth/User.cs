namespace UserLoginAuth
{
    public class User
    {
        public string username { get; set; } = string.Empty;
        public byte[] password { get; set; }
        public byte[] conformpassword { get; set; }
    }
}