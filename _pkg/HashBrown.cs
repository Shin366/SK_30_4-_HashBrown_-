// HashBrown 단일 실행 런처 (.NET Framework, -target:winexe → 콘솔 없음)
// 임베드된 웹 자산(index.html/main.js/main.css/favicon.svg)을
// %LOCALAPPDATA%\HashBrown\ 에 추출하고, Edge/Chrome 을 --app 모드로 띄운다.
// (없으면 기본 브라우저로 폴백)
using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;

static class HashBrownApp
{
    static void Extract(Assembly asm, string res, string outPath)
    {
        using (Stream s = asm.GetManifestResourceStream(res))
        {
            if (s == null) return;
            using (FileStream fs = File.Create(outPath))
                s.CopyTo(fs);
        }
    }

    [STAThread]
    static void Main()
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HashBrown");
        try
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            Directory.CreateDirectory(dir);
            Extract(asm, "index.html", Path.Combine(dir, "index.html"));
            Extract(asm, "main.js", Path.Combine(dir, "main.js"));
            Extract(asm, "main.css", Path.Combine(dir, "main.css"));
            Extract(asm, "favicon.svg", Path.Combine(dir, "favicon.svg"));

            string indexPath = Path.Combine(dir, "index.html");
            string url = "file:///" + indexPath.Replace("\\", "/");

            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string[] browsers = {
                Path.Combine(pfx86, @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(pf,    @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(pf,    @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(pfx86, @"Google\Chrome\Application\chrome.exe"),
            };
            foreach (string b in browsers)
            {
                if (File.Exists(b))
                {
                    Process.Start(b, "--app=\"" + url + "\" --window-size=1480,940");
                    return;
                }
            }
            // 폴백: 기본 브라우저(UseShellExecute)
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception e)
        {
            try { File.WriteAllText(Path.Combine(dir, "error.log"), e.ToString()); }
            catch { }
        }
    }
}
