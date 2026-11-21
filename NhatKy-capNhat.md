# Nhật ký cập nhật

## 2026-11-21 — Dọn màn hình menu quản trị

- Xóa màn hình trước khi vẽ menu và trước khi hiển thị nội dung lựa chọn, tránh nối kết quả cũ với menu mới.
- Giữ thông báo lỗi nhập lựa chọn trên màn hình đến khi nhấn Enter. Chỉ xóa cửa sổ tương tác, không chèn mã điều khiển khi chuyển hướng đầu ra.
- Đồng bộ script quản trị trong gói server và mã SHA-256, tạo ZIP cập nhật riêng.

## 2026-11-21 — Menu CMD quản trị và điều khiển an toàn

- Thêm `admin_wail2ban.bat` và menu PowerShell tiếng Việt với 13 lựa chọn quản trị; thoát menu không dừng bảo vệ.
- Menu xem được snapshot khi chưa nâng quyền. Thao tác thay đổi yêu cầu quyền quản trị và xác nhận đúng `tôi đồng ý`; không tự nâng quyền hoặc đổi Execution Policy.
- Bổ sung trình thêm/xóa whitelist, giữ mã hóa/xuống dòng/chú thích và các mục khác, kiểm tra toàn bộ cấu hình, sao lưu nguyên byte và phát hiện chỉnh sửa ngoài trước khi thay thế nguyên tử.
- Phân biệt whitelist đang lưu với snapshot đã nạp. Lưu không tự chạy lại bảo vệ hoặc gỡ rule hiện có.
- Bổ sung khóa bảo vệ dùng chung trên máy, phát hiện phiên cũ, khởi động ẩn và xác nhận theo PID/mã phiên. Dừng có kiểm soát, không cưỡng bức kết thúc tiến trình; chạy lại chỉ sau xác nhận dừng.
- Hàng đợi điều khiển theo mã yêu cầu và phiên đích hỗ trợ gỡ một IP, gỡ tất cả và dừng; có dấu chống thực thi lặp và phản hồi để đối chiếu.
- Gỡ chặn khi đang chạy cập nhật cùng bộ nhớ và lịch sử. Kết quả một phần giữ lịch sử IP chưa gỡ được và hiển thị danh sách tương ứng.
- Thêm bộ kiểm thử cho menu, trình sửa INI và điều khiển; các thao tác hệ thống đều dùng mock hoặc dữ liệu tạm, không tác động firewall/server thật.
- Đồng bộ thư mục `script`, mã SHA-256 và gói ZIP mới; giữ bản ZIP cũ. Không cài Scheduled Task hoặc dịch vụ.
- Kết quả kiểm thử đầy đủ trên Windows PowerShell 5.1.26100.9818: lõi 57, monitor 50, tích hợp 7, trình sửa cấu hình 56, điều khiển 38 và menu 39 kiểm tra đều đạt; 15 script không lỗi cú pháp.
- Đã chạy BAT thật với `-Help` và chọn `0` để thoát; vòng điều khiển/khởi động/dừng và firewall được kiểm tra bằng mock. Rà soát độc lập xác nhận sửa nhận diện tiến trình legacy và xung đột atomic replace khi lưu INI; thay đổi ngoài được giữ trong backup thực tế và khôi phục nếu an toàn, nếu xung đột tiếp thì báo đường dẫn phục hồi thủ công.

## 2026-11-21 — Hiển thị whitelist đã nạp trên monitor

- Snapshot bổ sung whitelist đang được tiến trình sử dụng, danh sách IP máy chủ tự miễn chặn, đường dẫn cấu hình và thời điểm nạp UTC. Giữ khả năng đọc snapshot cũ.
- Monitor terminal và HTML phân biệt whitelist rỗng với snapshot phiên bản cũ chưa có dữ liệu whitelist; không đọc file INI trực tiếp để tránh báo nhầm cấu hình chưa áp dụng.
- Thông báo lỗi cấu hình whitelist chỉ rõ số dòng và cú pháp, nhắc bỏ dấu backtick/dấu nháy. Cập nhật chú thích cấu hình mẫu để tránh sao chép nhầm dấu định dạng.
- Đồng bộ gói `script` và mã SHA-256 sau thay đổi; hướng dẫn giữ cấu hình và lịch sử hiện có khi cập nhật server.
- Kiểm thử mô phỏng cấu hình có backtick theo ảnh, cấu hình hợp lệ, chuyển dữ liệu từ cấu hình sang snapshot/monitor và sửa INI chưa nạp lại. Không thao tác server hoặc firewall thật.
- Kết quả Windows PowerShell 5.1.26100.9818: 56 kiểm tra lõi, 50 assertion monitor, 7 ca tích hợp đạt; 9 script không lỗi cú pháp. Đã mở HTML mẫu bằng trình duyệt và rà soát độc lập phần tương thích snapshot cũ/escape HTML.

## 2026-11-21 — Đóng gói thư mục script cho server

- Thêm thư mục `script` chứa năm tệp PowerShell chạy thực tế, cấu hình mẫu và giấy phép; không kèm Git, kiểm thử, nhật ký hoặc dữ liệu chặn.
- Thêm hai launcher `.bat` gọi Windows PowerShell 5.1 theo vị trí tệp, hỗ trợ đường dẫn có khoảng trắng và giữ tiến trình bảo vệ ở tiền cảnh.
- Thêm hướng dẫn tiếng Việt về cấu hình whitelist, chạy, monitor, gỡ chặn và sao lưu/khôi phục. Giữ nguyên launcher và task XML cũ bên ngoài gói.
- Bổ sung danh sách SHA-256 để đối chiếu tệp trong gói với mã nguồn và kiểm tra sau khi sao chép.
- Kiểm tra thực tế: 7/7 tệp sao chép khớp mã nguồn, 10/10 mã SHA-256 đúng; hai launcher chạy được từ thư mục khác bằng các lệnh `-help`, `-config`, monitor `-Once` trên Windows PowerShell 5.1.
- Chỉ đóng gói cục bộ; không kết nối server, không chạy bảo vệ thật, không sửa firewall và không cài tác vụ khởi động.

## 2026-11-21 — Giai đoạn 1: sửa lõi và bổ sung giám sát

### Thay đổi

- Tách logic xử lý khỏi chương trình chạy và các thao tác Event Log, Windows Firewall để kiểm thử bằng dữ liệu giả.
- Giữ Windows PowerShell 5.1, ngưỡng 5 lần thất bại trong 120 giây và chính sách tăng thời gian chặn hiện có.
- Loại sự kiện quá hạn trước khi đếm; bỏ sự kiện có thời gian tương lai. Chống trùng bằng tên log và Record ID; chỉ xóa sự kiện vừa xử lý khỏi hàng đợi.
- Đọc đúng trường IP của sự kiện 4625 và kiểm tra provider. Với SQL Server 18456, ưu tiên địa chỉ có cấu trúc, sau đó mới xét cụm CLIENT ở cuối thông điệp.
- Chuẩn hóa IPv4, so địa chỉ máy chủ chính xác và giữ whitelist IP/CIDR. Chưa hỗ trợ nguồn IPv6 thuần.
- Kiểm tra và gỡ chặn hết hạn ngay khi chạy và theo chu kỳ 5 giây, kể cả khi không có sự kiện mới hoặc sự kiện đến liên tục. Thử lại khi gỡ chặn thất bại.
- Xác minh phạm vi và kết quả thao tác rule firewall. IP đã bị chặn không bị tăng mức phạt chỉ vì có thêm sự kiện.
- Dùng đường dẫn theo vị trí script. Ghi lịch sử chặn, snapshot JSON và báo cáo HTML qua file tạm rồi thay thế nguyên tử.
- Thêm monitor terminal và HTML cục bộ, làm mới 5 giây, cảnh báo heartbeat quá 30 giây. Lỗi đọc firewall hiển thị trạng thái không xác định.
- Bổ sung bộ đếm theo phiên, danh sách IP bị chặn và 20 lỗi/cảnh báo gần nhất. Ghi lỗi/cảnh báo vào nhật ký; không đưa toàn bộ thông điệp đăng nhập vào monitor.
- Bổ sung tài liệu tiếng Việt tiếp nối phần tiếng Anh trong README, hướng dẫn vận hành và khôi phục.
- Bổ sung bộ kiểm thử tự chứa, không yêu cầu Pester; loại dữ liệu chạy thực tế khỏi Git bằng `.gitignore`.

### Bằng chứng kiểm tra trước commit

- Chạy `powershell.exe -NoProfile -NonInteractive -File .\tests\run-tests.ps1` trên Windows PowerShell **5.1.26100.9818**: 56 kiểm tra lõi, 31 assertion monitor và 5 ca tích hợp đều đạt; 9 script không lỗi cú pháp.
- Kiểm thử dùng mock Event Log, Windows Firewall và đồng hồ; hàng đợi được kiểm tra bằng sự kiện tổng hợp trong tiến trình kiểm thử. Không thay đổi rule firewall thật.
- Báo cáo HTML đã được mở bằng trình duyệt với dữ liệu giả trong đợt triển khai: hiển thị tiếng Việt, cảnh báo heartbeat cũ và nội dung HTML đã escape.
- Rà soát độc lập xác nhận sửa lỗi trạng thái khi đọc Event Log thất bại, nhận nhầm rule giới hạn phạm vi và nhận địa chỉ single-host dạng `/32` hoặc netmask toàn bit 1.

### Giới hạn và bàn giao

- Chưa xác minh với Event Log và Windows Firewall thật trên server đích; chưa cài task, dịch vụ hoặc triển khai remote.
- Launcher `.bat` và task XML cũ chưa được nâng cấp; cần rà soát trước khi cài đặt thực tế.
- Commit chỉ lưu trong kho Git local theo yêu cầu; không push hoặc công bố lên remote.
