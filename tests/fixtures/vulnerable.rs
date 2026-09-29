// Fixture: every line that must be reported carries an "expect" marker naming the rule. Every other line
// must stay clean. The file only has to parse, not compile.

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::without_storage_info] // expect: FS004
	pub struct Pallet<T>(_);

	#[pallet::storage]
	pub type Members<T: Config> = StorageValue<_, Vec<T::AccountId>, ValueQuery>; // expect: FS004

	#[pallet::storage]
	#[pallet::unbounded]
	pub type Notes<T: Config> = StorageMap<_, Twox64Concat, u32, BoundedVec<u8, T::Max>>; // expect: FS004

	#[pallet::storage]
	pub type Scores<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, u64, ValueQuery>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
			for (who, score) in Scores::<T>::iter() { // expect: FS007
				let first = Members::<T>::get()[0]; // expect: FS008
				let _ = (who, score, first);
			}
			let _ = Scores::<T>::clear(u32::MAX, None); // expect: FS007
			Weight::zero()
		}

		fn integrity_test() {
			assert!(T::Max::get() > 0);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::zero())] // expect: FS006
		pub fn set_score(origin: OriginFor<T>, who: T::AccountId, score: u64) -> DispatchResult {
			let _caller = ensure_signed(origin)?;
			let old = Scores::<T>::get(&who);
			Scores::<T>::insert(&who, old + score); // expect: FS002
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::wipe())]
		pub fn wipe(_origin: OriginFor<T>, who: T::AccountId) -> DispatchResult { // expect: FS005
			Scores::<T>::remove(&who);
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::split())]
		pub fn split(origin: OriginFor<T>, total: u64, parts: u64) -> DispatchResult {
			ensure_root(origin)?;
			let share = total / parts; // expect: FS002
			let small = share as u32; // expect: FS003
			let members = Members::<T>::get();
			let who = members.first().cloned().unwrap(); // expect: FS001
			ensure!(small > 0, Error::<T>::Zero);
			Scores::<T>::insert(&who, share);
			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::lottery())]
		pub fn lottery(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let (seed, _) = T::Randomness::random(b"lottery"); // expect: FS010
			if seed.as_ref()[0] > 128 { // expect: FS008
				panic!("unlucky"); // expect: FS001
			}
			Self::payout(&who)
		}

		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::delegated())]
		pub fn delegated(origin: OriginFor<T>) -> DispatchResult {
			// Forwarding the origin counts as handling it.
			Self::do_delegated(origin)
		}

		/// Remove an expired score. Can be called by anyone once the score has expired.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::reap())]
		pub fn reap(_origin: OriginFor<T>, who: T::AccountId) -> DispatchResult { // expect: FS005
			let members = Members::<T>::get();
			let first = members.first().expect("checked non-empty above; qed"); // expect: FS001
			Scores::<T>::remove(first);
			Scores::<T>::remove(&who);
			Ok(())
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_idle(_n: BlockNumberFor<T>, limit: Weight) -> Weight {
			let mut meter = WeightMeter::with_limit(limit);
			for (who, _) in Scores::<T>::iter() { // expect: FS007
				if meter.try_consume(T::DbWeight::get().writes(1)).is_err() {
					break;
				}
				Scores::<T>::remove(&who);
			}
			meter.consumed()
		}
	}

	impl<T: Config> Pallet<T> {
		fn payout(who: &T::AccountId) -> DispatchResult {
			let bonus = Scores::<T>::get(who).checked_mul(2).expect("bounded"); // expect: FS001
			let raw = unsafe { core::mem::transmute::<u64, i64>(bonus) }; // expect: FS009
			let _ = raw;
			Ok(())
		}

		fn do_delegated(origin: OriginFor<T>) -> DispatchResult {
			let _ = ensure_signed(origin)?;
			Ok(())
		}
	}
}
