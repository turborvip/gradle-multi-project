package com.turborvip.core.model.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.turborvip.core.constant.EnumRole;
import com.turborvip.core.model.entity.base.AbstractBase;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;


@Getter
@Setter
@NoArgsConstructor
@Table(name = "roles",schema = "account")
@Entity
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Role extends AbstractBase {

    @Enumerated(EnumType.STRING)
    @Column(name = "role_name",unique = true)
    private EnumRole roleName;

    @OneToMany(mappedBy = "roles", cascade = {CascadeType.DETACH, CascadeType.PERSIST, CascadeType.MERGE, CascadeType.REFRESH}, orphanRemoval = true)
    @JsonInclude
    private Set<User> users = new HashSet<>();

    public Role(Long id, EnumRole enumRole) {
        this.id = id;
        this.roleName = EnumRole.valueOf(enumRole.name());
    }

    public Role(EnumRole enumRole) {
        this.roleName = EnumRole.valueOf(enumRole.name());
    }
}
