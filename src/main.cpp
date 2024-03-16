#include <windows.h>
#include <ctime>
#include <thread>
#include <chrono>
#include <fstream>
#include <ios>
#include <iostream>
#include <string>
#include <strsafe.h>

#include <winerror.h>

// #define DEBUG
#define LOG_OUTPUT

typedef enum{HOUR, MIN, SEC} TIME_IDX;
const int ALARM_TIME[3] = {23, 50, 0};
const int ALIVE_TIME = 8 * 60 * 1000;

const char VERSION[] = "1.1.1";

const int _oC = 277, _oD = 311, _oF = 370, _oG = 415, _oA = 466;
const int _C = 262, _D = 294, _E = 330, _F = 349, _G = 392, _A = 440, _B = 494;
const int oC = 554, oD = 622, oF = 740, oG = 831, oA = 932;
const int C = 523, D = 578, E = 659, F = 698, G = 784, A = 880, B = 988;
const int C_ = 1047, D_ = 1175, E_ = 1319, F_ = 1397, G_ = 1568, A_ = 1760, B_ = 1976;
const int oC_ = 1109, oD_ = 1245, oF_ = 1480, oG_ = 1661, oA_ = 1865;

const int T = 800; //一拍的长度
const int Stop = 800; //一拍休止符的长度

/*隐藏窗口*/
void hideWindow() {
    std::cout << "点击此窗口..." << std::endl;
	HWND hwnd = NULL;
	while (hwnd == NULL) {
        hwnd = GetForegroundWindow();
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
    ShowWindow(hwnd, SW_HIDE);
}

/*提升权限*/
bool improvePv() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) return false;
	if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) return false;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, NULL, NULL, NULL)) return false;
	return true;
}

/*关机*/
bool powerOffProc() {

#ifdef DEBUG
    std::cout << "power off!" << std::endl;
#else
	if (!improvePv() || !ExitWindowsEx(EWX_POWEROFF | EWX_FORCE, SHTDN_REASON_MAJOR_APPLICATION)) return false;
#endif

    return true;
}

void sound() {
    Beep(F, 2 * T);
    Beep(E, T);
    Beep(_B, T);
    Beep(550, 2 * T);
}

void shutdown() {
#ifndef DEBUG
    sound();
#endif
    bool res = true;

    std::thread thread_shutdown([&res]() {
#ifdef DEBUG
        std::cout << "wait for 8mins in t_shutdown" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
#else   
        std::this_thread::sleep_for(std::chrono::milliseconds(ALIVE_TIME));
#endif
        if (res) {
            res = powerOffProc();
        }
    });
    /* 
    HKEY hkey = nullptr;
    if (ERROR_SUCCESS != RegOpenKeyEx(HKEY_CURRENT_USER, "Control Panel\\Desktop\\", 0, KEY_WRITE, &hkey)) {
        throw "Unable to Open Regedit";
    }
    DWORD orig;
    DWORD value_type;
    DWORD sz;
    const BYTE targ_value[8] = {};
    HRESULT res_;
    if (ERROR_SUCCESS != (res_ = RegQueryValueEx(hkey, "ForegroundLockTimeout", 0, &value_type, (LPBYTE)&orig, &sz))) {
        std::cout << "Unable to query value" << std::endl;
        CHAR buffer[100+1];
        va_list args = NULL;
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE, 0, 0, 0, buffer, 0, &args);
        std::cout << buffer  << res_ << std::endl;
        throw "Exit";
    }
    if (ERROR_SUCCESS != RegSetValueEx(hkey, "ForegroundLockTimeout", 0, REG_DWORD, (const BYTE*)0x00'000'000, sizeof(DWORD))) {
        std::cout << "Unable to set value" << std::endl;
    }
    */ // 读取注册表使后台窗口跳到前台: Bug here: Unable to query value: Access denied

    std::thread thread_messagebox([&res]() {
        MessageBox(NULL, "还不关机？", "真得关机了吧关机吧真的", MB_OK | MB_SETFOREGROUND);
        res = false;
#ifdef DEBUG
        std::cout << "wait for 5mins in t_messagebox" << std::endl;
#else
        std::this_thread::sleep_for(std::chrono::milliseconds(5 * 60 * 1000));
#endif
        MessageBox(NULL, "还不关机？还不关机？还不关机？", "真得关机了吧关机吧真的", MB_OK| MB_SETFOREGROUND);
    });

    thread_messagebox.join();
    /*
    if (ERROR_SUCCESS != RegSetValueEx(hkey, "ForegroundLockTimeout", 0, REG_DWORD, (const BYTE*)0x00'030'd40, sizeof(DWORD))) {
        throw "Unable to change back";
    }
    RegCloseKey(hkey);
    */

    thread_shutdown.join();

}

bool is_time_to_shutdown(tm* cur_time_tm) {

    int weekday = cur_time_tm->tm_wday;
    int hour = cur_time_tm->tm_hour;
    int min = cur_time_tm->tm_sec;

#ifdef DEBUG
    return false;
#else
    return weekday <= 4 && hour >= ALARM_TIME[HOUR] && min >= ALARM_TIME[MIN];
#endif

}

void update_time_tm(tm* old_time_tm, tm* new_time_tm) {
    int MONDAYS[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int YEARDAYS  = 365;
    new_time_tm->tm_sec = ALARM_TIME[SEC];
    new_time_tm->tm_min = ALARM_TIME[MIN];
    new_time_tm->tm_hour = ALARM_TIME[HOUR];
    new_time_tm->tm_mon = old_time_tm->tm_mon;
    new_time_tm->tm_year = old_time_tm->tm_year;
    new_time_tm->tm_isdst = old_time_tm->tm_isdst;

    if (new_time_tm->tm_year % 4 == 0) {
        MONDAYS[1] = 29;
        YEARDAYS  = 366;
    }

    new_time_tm->tm_wday = old_time_tm->tm_wday;
    new_time_tm->tm_mday = old_time_tm->tm_mday;
    new_time_tm->tm_yday = old_time_tm->tm_yday;

    if (new_time_tm->tm_wday > 4) {
        int passing_days = 7 - new_time_tm->tm_wday;
        new_time_tm->tm_wday = 0;

        new_time_tm->tm_mday += passing_days;
        new_time_tm->tm_yday += passing_days;

        if (new_time_tm->tm_mday >  MONDAYS[new_time_tm->tm_mon]) {
            new_time_tm->tm_mday %= MONDAYS[new_time_tm->tm_mon];
            new_time_tm->tm_mon++;
        }

        if (new_time_tm->tm_mon  >= 12 && new_time_tm->tm_yday >= YEARDAYS) {
            new_time_tm->tm_mon  %= 12;
            new_time_tm->tm_yday %= YEARDAYS;
            new_time_tm->tm_year++;
        }
    }
}



int main() {

#ifndef DEBUG
    hideWindow();
#endif

    while (true) {

        time_t now = time(nullptr);
        tm *cur_time_tm = localtime(&now);

#ifdef DEBUG
        std::cout << asctime(cur_time_tm) << std::endl;
#endif

#ifdef LOG_OUTPUT
        std::fstream log_file;
        log_file.open("./log.log", std::ios::out | std::ios::app);
        log_file << "This programe start at " << asctime(cur_time_tm) << std::endl;
#endif

        if (!is_time_to_shutdown(cur_time_tm)) {
            tm *new_time_tm;
            update_time_tm(cur_time_tm, new_time_tm);

#ifdef DEBUG
            std::cout << "Ready to shutdown at " << asctime(new_time_tm) << std::endl;
#endif
#ifdef LOG_OUTPUT
            log_file << "Ready to shutdown at " << asctime(new_time_tm) << std::endl;
#endif

            std::chrono::time_point shutdown_time = std::chrono::system_clock::from_time_t(mktime(new_time_tm));
#ifdef DEBUG
            std::cout << "waiting for shutdown" << std::endl;
#else
            std::this_thread::sleep_until(shutdown_time);
#endif
        }
#ifdef LOG_OUTPUT
        else {
            log_file << "And is ready to restart" << std::endl;
            log_file.close();
        }
#endif

        shutdown();

#ifdef LOG_OUTPUT
        time_t now_ = time(nullptr);
        tm *cur_time_tm_ = localtime(&now);

        log_file.open("./log.log", std::ios::out | std::ios::app);
        log_file << "FAILED SHUTDOWN at " << asctime(cur_time_tm) << std::endl;
        log_file.close();
#endif
    }

    return 0;
}