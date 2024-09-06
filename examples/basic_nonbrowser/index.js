import namedrop from '../../index.js';

//namedrop.setApiUri('https://anderspitman.com/namedrop'); 

const client = new namedrop.Client({
  token: '<token here>',
});

const records = await client.getRecords();
console.log(records);

try {
  await client.setRecords({
    records: [
      {
        type: 'A',
        value: '127.0.0.2',
      },
    ],
  });
}
catch (e) {
  console.error(e);
}
