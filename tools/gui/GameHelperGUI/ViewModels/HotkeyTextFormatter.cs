namespace GameHelperGUI.ViewModels;

public static class HotkeyTextFormatter
{
    public static string Format(int vk)
    {
        if (vk <= 0)
        {
            return "未绑定";
        }
        switch (vk)
        {
            case 0x24:
                return "Home";
            case 0x2D:
                return "Insert";
            case 0x2E:
                return "Delete";
            case 0x70:
                return "F1";
            case 0x71:
                return "F2";
            case 0x72:
                return "F3";
            case 0x73:
                return "F4";
            case 0x74:
                return "F5";
            case 0x75:
                return "F6";
            case 0x76:
                return "F7";
            case 0x77:
                return "F8";
            case 0x78:
                return "F9";
            case 0x79:
                return "F10";
            case 0x7A:
                return "F11";
            case 0x7B:
                return "F12";
            case 0x30:
                return "0";
            case 0x31:
                return "1";
            case 0x32:
                return "2";
            case 0x33:
                return "3";
            case 0x34:
                return "4";
            case 0x35:
                return "5";
            case 0x36:
                return "6";
            case 0x37:
                return "7";
            case 0x38:
                return "8";
            case 0x39:
                return "9";
            case 0xBD:
                return "-";
            default:
                return $"0x{vk:X2}";
        }
    }
}
