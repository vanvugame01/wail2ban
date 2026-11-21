# wail2ban

[![No Maintenance Intended](http://unmaintained.tech/badge.svg)](http://unmaintained.tech/)

![Saddest Whale](http://i.imgur.com/NVlsY.png "Saddest Whale")

wail2ban is a windows port of the basic functionality of [fail2ban](http://www.fail2ban.org/), and combining elements of [ts_block](https://github.com/EvanAnderson/ts_block).

## overview

wail2ban is a system that takes incoming failed access events for a customly configurable set of known event ids, and given sufficient failed attacks in a period of time, creates temporary firewall rules to block access.

## installation

Installing wail2ban is a case of a view simple tasks:

- copy all the repository files to a location on the client machine, e.g. `C:\scripts\wail2ban`
- Using Task Scheduler, import the `start wail2ban onstartup.xml` file to automatically create a scheduled task to start the script when the machine boots.
- Initiate the script by running the `start wail2ban.bat` file. This is what the scheduled task starts.

## commandline execution

wail2ban has `write-debug` things through it, just uncomment the `$DebugPreference` line to enable. This will output nice things to CMD, if running ad-hoc.

There are also a number of options that can be run against the script to control it:

- `-config` : dumps a parsed output of the configuration file to standard out, including timing and whitelist configurations.
- `-jail` : shows the current set of banned IPs on the machine
- `-jailbreak`: unbans every IP currently banned by the script.

## technical overview

Event logs for various software packages are configured to produce messages when failed connections occur. The contents of the events usually contain an IP, an a message something along the lines of "This IP failed to connect to your server."

Typical examples of this include:

- Security Event ID 4625, "Windows Security Auditing".
- `An account failed to log in. ... Source Network Address: 11.22.33.44`

Database products also include these kind of events, such as:

- Application Event ID 18456, "Microsoft SQL Server".
- `Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 11.22.33.44]`

These events are produced any time someone mistypes a password, or similar.

The issue occurs when automated brute-force entry systems attempt to access systems multiple times a second.

## what wail2ban does

wail2ban is a real-time event sink for these messages. As messages come in, wail2ban takes note of the time of the attempt and the IP used in the attempt. Given enough attempts in a specific period of time, wail2ban will generate a firewall rule to block all access to the client machine for a certain period of time.

In a default setup, if an IP attempts 5 failed passwords in a 2 minute period, they get banned from attempting again for a period of time.

How long? Well, that depends on how many times they've been banned before!

There is a file called BannnedIPLog.ini that will keep a count of how many times an IP has been banned.

The punishment time is based on the function `y=5^x`, where x is the amount of times it has been banned, and y is the amount of minutes it's banned for.

This allows for scaling of bans, but prevent permenant bans, which may cause issues in the future as IPs are reassigned around the blagosphere.

There is also a `$MAX_BANDURATION` in place, which means that an IP cannot be banned for more than 3 months. Given the ban duration function gives values of years at the 10th increment, it's better to cap things out.

## failsafes

As with all automated systems, there can be some false-positives.

**Whitelists** - this script can be configured with a whitelist of IPs that it will never ban, such as a company IP block.

**Self-list** - the script automatically adds a set of IPs to the whitelist that it knows as not to ban, based on the configured static IPs on the host machine. That is, it will ignore attempts from itself (or event logs which list it's own IP in the message).

**Timeouts** - IPs are only banned for specific period of time. After this time, they are removed from the firewall by the script. The timeouts are parsed once a new failed attempt is captured by the system. This may mean that IPs are unbanned after their exact unlock time, but for sufficiently attacked systems, this difference is not a major issue.

**Jailbreak** - a configuration called `-jailbreak` can be run against the script at any time to immediately remove all banned IPs. All their counters are reset, and it is as if the IP never tried to attack the machine.

## htmlgen

I've added a script that will grep the wail2ban log file, and generate some nice statistics, and show the top banned IPs by country.
[Sample Report](http://i.imgur.com/ufb9mvX.png)

If you want to enable this, grok the main wail2ban.ps1 script for the call to `wail2ban_htmlgen.ps1`, and enable it (remove the comment)

## limitations

There can be improvements relating to the service-like execution of this script, so it's always running. This can be acheieved using something like [non-sucking service manager](http://nssm.cc/), but that is left as an exercise for the reader.

Update 2020: There have been several on and off repo communications saying this code is still useful! I don't have any way to test the following, but hopefully the following may help:

- Thanks to Marco Jonas, `BLOCK_TYPE` is set to `netsh`, which I presume still exists.
- Thanks to Gl0, you can add SSL RDP Login support with [this patch](https://github.com/glasnt/wail2ban/pull/13/files)
- Thanks to kentuckytech, add `-executionpolicy bypass -file` to the .bat file if you require a bypass.

---

## Sau đây là phần tiếp nối phát triển của dự án

---

## Tài liệu tiếng Việt — giai đoạn 1

Wail2ban theo dõi đăng nhập thất bại trên Windows và tạo rule Windows Firewall tạm thời. Bản nâng cấp này sửa logic đếm, gỡ chặn và bổ sung monitor terminal/HTML cục bộ.

### Nền tảng và chính sách

- Windows PowerShell **5.1**, chạy trên Windows. Chưa hỗ trợ PowerShell 7.
- Mặc định: 5 lần thất bại trong 120 giây. Thời gian phạt là `min(5^n × 60, 7776000)` giây, với `n` là số lần ban của IP.
- Giữ cấu hình `wail2ban_config.ini` và định dạng `bannedIPLog.ini` hiện có. IP đã có rule chặn không bị tăng mức phạt chỉ vì có sự kiện mới.
- Hỗ trợ IPv4 và whitelist IPv4/CIDR; chưa hỗ trợ nguồn IPv6 thuần.
- Sự kiện 4625 bao gồm nhiều loại đăng nhập thất bại, không chỉ RDP. Chính sách hiện tại vẫn áp dụng các loại đăng nhập như trước.
- Với 4625, đọc trường `IpAddress` từ XML của đúng bản ghi và provider. Với SQL Server 18456, ưu tiên trường địa chỉ có cấu trúc; chỉ dùng cụm `[CLIENT: ...]` cuối thông điệp khi cần. Không xác định được IPv4 hợp lệ thì bỏ qua và ghi cảnh báo.
- Gỡ ban hết hạn ngay khi khởi động và kiểm tra định kỳ 5 giây. Lệnh gọi Windows chậm có thể làm chu kỳ thực tế trễ hơn; lỗi gỡ ban sẽ được thử lại.

### Chạy và theo dõi

Các lệnh dưới đây dành cho **Windows PowerShell 5.1**. Việc chạy chương trình bảo vệ thật cần quyền đọc Security Event Log và quản lý Windows Firewall. Chỉ chạy sau khi đã kiểm tra cấu hình, whitelist quản trị và phương án khôi phục.

Trong thư mục dự án:

```powershell
powershell.exe -NoProfile -File .\wail2ban.ps1 -help
powershell.exe -NoProfile -File .\wail2ban.ps1 -config

# Chi chay lenh nay khi da san sang bat bao ve that.
powershell.exe -NoProfile -File .\wail2ban.ps1
```

Mở terminal khác để theo dõi, thoát bằng `Ctrl+C`:

```powershell
powershell.exe -NoProfile -File .\wail2ban_monitor.ps1
powershell.exe -NoProfile -File .\wail2ban_monitor.ps1 -Once
```

Hoặc mở `public_html/index.html` bằng trình duyệt. File được tạo sau khi chương trình xuất trạng thái. Trang tự tải lại mỗi 5 giây, hoạt động ngoại tuyến và không cần web server. Không có thao tác chặn/gỡ chặn trên monitor.

Tạo lại báo cáo từ snapshot hiện có:

```powershell
powershell.exe -NoProfile -File .\wail2ban_htmlgen.ps1
```

Đường dẫn dữ liệu tính theo vị trí script, không theo thư mục gọi:

| Tệp                            | Nội dung                                               |
| ------------------------------ | ------------------------------------------------------ |
| `runtime/wail2ban_status.json` | Snapshot phục vụ cả hai monitor, định dạng phiên bản 1 |
| `public_html/index.html`       | Báo cáo HTML cục bộ                                    |
| `wail2ban_log.log`             | Nhật ký hành động, lỗi và cảnh báo                     |
| `bannedIPLog.ini`              | Số lần ban tích lũy theo IP                            |

Snapshot chứa hostname, PID, mã phiên chạy, thời điểm bắt đầu/heartbeat UTC, bộ đếm từ lần khởi động, danh sách ban và tối đa 20 lỗi/cảnh báo gần nhất. Không lưu toàn bộ thông điệp đăng nhập vào monitor. Snapshot và HTML được ghi qua file tạm rồi thay thế nguyên tử.

### Hiểu trạng thái monitor

- **Đang chạy:** vòng xử lý vừa cập nhật heartbeat.
- **Có lỗi:** chương trình ghi nhận tình trạng lỗi; xem cảnh báo gần nhất và nhật ký.
- **Heartbeat quá hạn:** quá 30 giây không có heartbeat mới. Có thể tiến trình đã chết hoặc đang bị kẹt.
- **Đã dừng:** chương trình ghi nhận dừng có kiểm soát. Khi bị kill hoặc mất điện, monitor dựa vào heartbeat quá hạn.
- **Chưa có dữ liệu:** snapshot chưa tồn tại hoặc không đọc/kiểm tra được.
- **Không xác định:** không đọc được firewall; không được hiểu là không có IP bị chặn.

Heartbeat chỉ xác nhận vòng xử lý còn hoạt động. Nó không chứng minh audit policy, nguồn sự kiện hay firewall hoạt động đầy đủ. Cảnh báo heartbeat trên HTML vẫn được tính bằng JavaScript khi chương trình chính đã dừng cập nhật.

### Lệnh quản trị

```powershell
powershell.exe -NoProfile -File .\wail2ban.ps1 -jail

# Cac lenh duoi day thay doi firewall va lich su ban.
powershell.exe -NoProfile -File .\wail2ban.ps1 -unban 203.0.113.9
powershell.exe -NoProfile -File .\wail2ban.ps1 -jailbreak
```

Monitor chỉ đọc snapshot, không cần tự sửa firewall. Các lệnh quản trị phải được người vận hành chủ động thực hiện. Bản bàn giao không cài task/service hoặc thay đổi quyền truy cập.

### Kiểm thử an toàn

```powershell
powershell.exe -NoProfile -NonInteractive -File .\tests\run-tests.ps1
```

Bộ kiểm thử tự chứa, không cần Pester; mock Event Log, firewall và đồng hồ. Dữ liệu kiểm thử nằm trong thư mục tạm. Không khởi chạy listener thật, không tạo/xóa rule firewall thật và không yêu cầu quyền quản trị.

Các trường hợp kiểm tra gồm cửa sổ thời gian, chống sự kiện lặp, trùng Record ID giữa các log, giữ sự kiện trong hàng đợi, parser IP, whitelist, gỡ ban khi im lặng, lỗi gỡ ban và thử lại, snapshot lỗi, trạng thái cũ và escape HTML. `-LibraryOnly` dùng để nạp logic/adapter trong kiểm thử mà không khởi động bảo vệ.

### Triển khai và khôi phục sau này

Trước khi đưa lên server, lưu bản code, cấu hình, lịch sử ban và các rule thuộc Wail2ban. Ghi lại phiên bản Windows, PowerShell, audit policy và tài khoản chạy. Kiểm tra bằng sự kiện mẫu thực tế, đặc biệt với SQL Server và đường đăng nhập RDP/NLA của hệ thống.

Nếu cần quay lại: dừng tiến trình Wail2ban mới có kiểm soát, khôi phục code/cấu hình/lịch sử đã sao lưu rồi khởi chạy bản trước. Việc dừng chương trình không tự xóa các rule đang chặn. Nếu phải thay đổi rule, đối soát đúng rule thuộc Wail2ban và thực hiện trong cửa sổ quản trị được cho phép; không xóa toàn bộ firewall.

Launcher `.bat` và task XML cũ chưa được nâng cấp trong giai đoạn này. Chúng vẫn chứa đường dẫn cài đặt cố định; không nhập task hoặc chạy launcher trước khi rà soát. Chưa bổ sung supervisor, cơ chế đa tiến trình, nâng cấp PowerShell 7 hoặc quản trị qua mạng.

**Giới hạn nghiệm thu:** kiểm thử mô phỏng không thay thế xác minh Event Log và Windows Firewall thật trên server đích. Việc triển khai server là bước riêng.

Mã nguồn gốc dựa trên Wail2ban của glasnt; xem `LICENCE.md`.
