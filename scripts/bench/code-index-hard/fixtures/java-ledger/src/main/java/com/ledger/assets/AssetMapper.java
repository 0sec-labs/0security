package com.ledger.assets;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class AssetMapper {

    public AssetDto toDto(Asset e) {
        return new AssetDto(e.id(),
                e.label(), e.serialNumber(), e.purchasedOn(),
                e.valueCents());
    }

    public Asset create(AuthUser user, AssetDto dto) {
        return new Asset(Ids.next("ast"), user.tenantId(), user.id(),
                Text.required(dto.label(), "label"), Text.plain(dto.serialNumber()), dto.purchasedOn(),
                dto.valueCents());
    }

    public Asset apply(Asset current, AssetDto dto) {
        return new Asset(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.label(), "label"), Text.plain(dto.serialNumber()), dto.purchasedOn(),
                dto.valueCents());
    }
}
