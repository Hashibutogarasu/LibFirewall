use super::query::{Query, QueryBuilder};

pub struct QueryResult<T> {
    pub result: T,
}

pub struct QueryExecutor;

impl QueryExecutor {
    pub fn execute<Q, B>(builder: B) -> QueryResult<Q::Output>
    where
        Q: Query,
        B: QueryBuilder<Query = Q>,
    {
        let query = builder.build();
        let result = query.execute();
        QueryResult { result }
    }
}
