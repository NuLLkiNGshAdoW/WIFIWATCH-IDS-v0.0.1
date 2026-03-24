namespace diplom2
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            // ЭТА СТРОКА ДОЛЖНА БЫТЬ ПЕРВОЙ:
            Application.SetHighDpiMode(HighDpiMode.DpiUnaware);

            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }
    }
}