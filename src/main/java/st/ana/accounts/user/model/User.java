package st.ana.accounts.user.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import javax.annotation.Nullable;
import java.time.Instant;
import java.util.Set;

@Entity
public class User {
    @Id
    private Long id; // 아이디
    @Column(unique = true)
    private String handle; // 헨들
    @Column(unique = true)
    private String googleId; // 구글 연동
    @Column(unique = true)
    private String email; // 이메일 (개인 이메일 등록 가능; NULLABLE)
    private int generation; // 기수 (-1이라면 MEMBER가 아님)
    @Column(nullable = false)
    private String name; // 실명
    @Column(name = "phone_number")
    private String phoneNumber;
    @Nullable
    private String password; // password가 null일시에는 구글으로만 로그인 가능.
    private Set<String> roles;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
