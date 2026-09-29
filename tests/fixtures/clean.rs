// Fixture: idiomatic pallet code plus code that only runs off-chain. Nothing may be reported.

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	pub type Members<T: Config> =
		StorageValue<_, BoundedVec<T::AccountId, T::MaxMembers>, ValueQuery>;

	#[pallet::storage]
	pub type Scores<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, u64, ValueQuery>;

	const HALF: u64 = u64::MAX / 2 + 1;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn integrity_test() {
			assert!(T::MaxMembers::get() > 0, "need members");
		}

		#[cfg(feature = "try-runtime")]
		fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			assert_eq!(Members::<T>::get().len(), Members::<T>::get().len());
			Ok(())
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			let members: BoundedVec<_, _> = self.members.clone().try_into().expect("genesis fits");
			Members::<T>::put(members);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_score())]
		pub fn add_score(origin: OriginFor<T>, who: T::AccountId, score: u64) -> DispatchResult {
			ensure_signed(origin)?;
			let total = Scores::<T>::get(&who).checked_add(score).ok_or(Error::<T>::Overflow)?;
			let half = total / 2;
			Scores::<T>::insert(&who, total.saturating_sub(half));
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::first())]
		pub fn first(origin: OriginFor<T>) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			let members = Members::<T>::get();
			let who = members.first().ok_or(Error::<T>::NoMembers)?;
			let limit: u32 = members.len().try_into().map_err(|_| Error::<T>::Overflow)?;
			ensure!(limit > 0, Error::<T>::NoMembers);
			Scores::<T>::remove(who);
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::known())]
		pub fn known(origin: OriginFor<T>, idx: u32) -> DispatchResult {
			ensure_signed(origin)?;
			// A reviewed, bounds-checked index, suppressed explicitly.
			let members = Members::<T>::get();
			ensure!((idx as usize) < members.len(), Error::<T>::NoMembers);
			// sentinel:allow(FS008)
			let _who = &members[idx as usize];
			Ok(())
		}
	}

	#[cfg(test)]
	mod tests {
		#[test]
		fn anything_goes_in_tests() {
			let v = vec![1u64];
			assert_eq!(v[0] + 1, 2);
			Some(1).unwrap();
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl<T: Config> Pallet<T> {
		fn bench_setup() {
			Members::<T>::get().first().unwrap();
		}
	}
}
