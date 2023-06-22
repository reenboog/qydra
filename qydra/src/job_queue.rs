use core::hash::Hash;
use std::{collections::HashMap, future::Future, sync::Arc};
use tokio::sync::{oneshot, Mutex};

/// A concurrent queue that doesn't allow parallel execution for tasks with the same key
pub struct Queue<Key> {
	tasks: Arc<Mutex<HashMap<Key, oneshot::Receiver<()>>>>,
}

impl<Key> Queue<Key>
where
	Key: Eq + Hash,
{
	pub fn new() -> Self {
		Self {
			tasks: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	pub async fn push<F, T>(&self, key: Key, f: impl FnOnce() -> F) -> T
	where
		F: Future<Output = T>,
	{
		let (tx, rx) = oneshot::channel();
		let tasks = self.tasks.clone();

		let t = {
			let key = key;
			let mut tasks = tasks.lock().await;
			let t = tasks.remove(&key);

			tasks.insert(key, rx);

			t
		};

		if let Some(t) = t {
			t.await.unwrap_or(());
		}

		let res = f().await;

		tx.send(()).unwrap_or(());

		res
	}
}

#[cfg(test)]
mod tests {
	use super::Queue;
	use rand::{seq::SliceRandom, Rng};
	use std::{
		sync::{Arc, Mutex},
		time::Duration,
	};
	use tokio::time::sleep;

	// keeps track of running tasks

	struct Worker {
		queue: Queue<u8>,
		active_tasks: Mutex<Vec<u8>>,
	}

	impl Worker {
		fn new() -> Self {
			Self {
				queue: Queue::new(),
				active_tasks: Mutex::new(Vec::new()),
			}
		}

		async fn do_work(&self, nid: u8, r: u64) {
			self.queue
				.push(nid, || {
					let mut pendings = self.active_tasks.lock().unwrap();

					// make sure tasks with the same key can't run in parallel
					assert!(!pendings.contains(&nid));
					pendings.push(nid);

					let res = async {
						// a delay to make things a bit random
						sleep(Duration::from_millis(r)).await
					};

					let index = pendings.iter().position(|e| *e == nid).unwrap();
					pendings.remove(index);

					res
				})
				.await
		}
	}

	#[tokio::test]
	async fn test_tasks_executed_in_parallel_if_not_same_key() {
		let worker = Arc::new(Worker::new());
		let mut rng = rand::thread_rng();
		let total_tests = 20;

		for unique_keys in 1..total_tests {
			let ops = (0..total_tests)
				.collect::<Vec<u8>>()
				.iter()
				.map(|_| rng.gen::<u8>() % unique_keys)
				.collect::<Vec<u8>>();
			let mut tasks = Vec::new();

			for i in 0..ops.len() {
				let nid = ops[i];
				let r = rng.gen::<u64>() % 10;
				let q = worker.clone();

				tasks.push(tokio::spawn(async move { q.do_work(nid, r).await }));
			}

			tasks.shuffle(&mut rng);

			for i in 0..tasks.len() {
				_ = tasks.get_mut(i).unwrap().await;
			}
		}
	}
}
