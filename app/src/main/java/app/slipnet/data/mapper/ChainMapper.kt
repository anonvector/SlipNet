package app.slipnet.data.mapper

import app.slipnet.data.local.database.ChainEntity
import app.slipnet.domain.model.ProfileChain
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

object ChainMapper {
    private val gson = Gson()
    private val listType = object : TypeToken<List<Long>>() {}.type

    fun toDomain(entity: ChainEntity): ProfileChain = ProfileChain(
        id = entity.id,
        name = entity.name,
        profileIds = gson.fromJson(entity.profileIdsJson, listType),
        isActive = entity.isActive,
        createdAt = entity.createdAt,
        updatedAt = entity.updatedAt,
        sortOrder = entity.sortOrder
    )

    fun toEntity(chain: ProfileChain): ChainEntity = ChainEntity(
        id = chain.id,
        name = chain.name,
        profileIdsJson = gson.toJson(chain.profileIds),
        isActive = chain.isActive,
        createdAt = chain.createdAt,
        updatedAt = chain.updatedAt,
        sortOrder = chain.sortOrder
    )
}
