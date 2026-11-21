# Nhật ký cập nhật

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
